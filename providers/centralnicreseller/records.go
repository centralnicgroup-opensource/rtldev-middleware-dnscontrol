package centralnicreseller

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/diff"
	"github.com/StackExchange/dnscontrol/v4/pkg/txtutil"
)

// CNRRecord covers an individual DNS resource record.
type CNRRecord struct {
	// DomainName is the zone that the record belongs to.
	DomainName string
	// Host is the hostname relative to the zone: e.g. for a record for blog.example.org, domain would be "example.org" and host would be "blog".
	// An apex record would be specified by either an empty host "" or "@".
	// A SRV record would be specified by "_{service}._{protocol}.{host}": e.g. "_sip._tcp.phone" for _sip._tcp.phone.example.org.
	Host string
	// FQDN is the Fully Qualified Domain Name. It is the combination of the host and the domain name. It always ends in a ".". FQDN is ignored in CreateRecord, specify via the Host field instead.
	Fqdn string
	// Type is one of the following: A, AAAA, ANAME, CNAME, MX, NS, SRV, or TXT.
	Type string
	// Answer is either the IP address for A or AAAA records; the target for ANAME, CNAME, MX, or NS records; the text for TXT records.
	// For SRV records, answer has the following format: "{weight} {port} {target}" e.g. "1 5061 sip.example.org".
	Answer string
	// TTL is the time this record can be cached for in seconds.
	TTL uint32
	// Priority is only required for MX and SRV records, it is ignored for all others.
	Priority uint32
}

// GetZoneRecords gets the records of a zone and returns them in RecordConfig format.
func (n *CNRClient) GetZoneRecords(domain string, meta map[string]string) (models.Records, error) {
	records, err := n.getRecords(domain)
	if err != nil {
		return nil, err
	}
	actual := make([]*models.RecordConfig, len(records))
	for i, r := range records {
		actual[i] = toRecord(r, domain)
	}

	for _, rec := range actual {
		if rec.Type == "ALIAS" {
			return nil, fmt.Errorf("we support realtime ALIAS RR over our X-DNS service, please get in touch with us")
		}
	}

	return actual, nil

}

// GetZoneRecordsCorrections returns a list of corrections that will turn existing records into dc.Records.
func (n *CNRClient) GetZoneRecordsCorrections(dc *models.DomainConfig, actual models.Records) ([]*models.Correction, error) {
	toReport, create, del, mod, err := diff.NewCompat(dc).IncrementalDiff(actual)
	if err != nil {
		return nil, err
	}
	// Start corrections with the reports
	corrections := diff.GenerateMessageCorrections(toReport)

	buf := &bytes.Buffer{}
	// Print a list of changes. Generate an actual change that is the zone
	changes := false
	params := map[string]interface{}{}
	delrridx := 0
	addrridx := 0
	for _, cre := range create {
		changes = true
		fmt.Fprintln(buf, cre)
		rec := cre.Desired
		recordString, err := n.createRecordString(rec, dc.Name)
		if err != nil {
			return corrections, err
		}
		params[fmt.Sprintf("ADDRR%d", addrridx)] = recordString
		addrridx++
	}
	for _, d := range del {
		changes = true
		fmt.Fprintln(buf, d)
		rec := d.Existing.Original.(*CNRRecord)
		params[fmt.Sprintf("DELRR%d", delrridx)] = n.deleteRecordString(rec)
		delrridx++
	}
	for _, chng := range mod {
		changes = true
		fmt.Fprintln(buf, chng)
		old := chng.Existing.Original.(*CNRRecord)
		new := chng.Desired
		params[fmt.Sprintf("DELRR%d", delrridx)] = n.deleteRecordString(old)
		newRecordString, err := n.createRecordString(new, dc.Name)
		if err != nil {
			return corrections, err
		}
		params[fmt.Sprintf("ADDRR%d", addrridx)] = newRecordString
		addrridx++
		delrridx++
	}
	msg := fmt.Sprintf("GENERATE_ZONEFILE: %s\n", dc.Name) + buf.String()

	if changes {
		corrections = append(corrections, &models.Correction{
			Msg: msg,
			F: func() error {
				return n.updateZoneBy(params, dc.Name)
			},
		})
	}

	return corrections, nil
}

func toRecord(r *CNRRecord, origin string) *models.RecordConfig {
	rc := &models.RecordConfig{
		Type:     r.Type,
		TTL:      r.TTL,
		Original: r,
	}
	fqdn := r.Fqdn[:len(r.Fqdn)-1]
	rc.SetLabelFromFQDN(fqdn, origin)

	switch rtype := r.Type; rtype {
	case "MX":
		if err := rc.SetTargetMX(uint16(r.Priority), r.Answer); err != nil {
			panic(fmt.Errorf("unparsable MX record received from hexonet api: %w", err))
		}
	case "SRV":
		if err := rc.SetTargetSRVPriorityString(uint16(r.Priority), r.Answer); err != nil {
			panic(fmt.Errorf("unparsable SRV record received from hexonet api: %w", err))
		}
	default: // "A", "AAAA", "ANAME", "CNAME", "NS"
		if err := rc.PopulateFromStringFunc(rtype, r.Answer, r.Fqdn, txtutil.ParseQuoted); err != nil {
			panic(fmt.Errorf("unparsable record received from hexonet api: %w", err))
		}
	}
	return rc
}

// func (n *CNRClient) showCommand(cmd map[string]string) error {
// 	b, err := json.MarshalIndent(cmd, "", "  ")
// 	if err != nil {
// 		return fmt.Errorf("error: %w", err)
// 	}
// 	printer.Printf(string(b))
// 	return nil
// }

func (n *CNRClient) updateZoneBy(params map[string]interface{}, domain string) error {
	zone := domain
	cmd := map[string]interface{}{
		"COMMAND": "ModifyDNSZone",
		"DNSZONE": zone,
	}
	for key, val := range params {
		cmd[key] = val
	}
	// n.showCommand(cmd)
	r := n.client.Request(cmd)
	if !r.IsSuccess() {
		return n.GetCNRApiError("Error while updating zone", zone, r)
	}
	return nil
}

func (n *CNRClient) getRecords(domain string) ([]*CNRRecord, error) {
	var records []*CNRRecord
	zone := domain

	// Command to query DNS zone records
	cmd := map[string]interface{}{
		"COMMAND": "QueryDNSZoneRRList",
		"DNSZONE": zone,
		"WIDE":    "1",
		"ORDERBY": "type",
	}

	// Make a request using the provided client
	r := n.client.Request(cmd)

	// Check if the request was successful
	if !r.IsSuccess() {
		if r.GetCode() == 545 {
			// Return specific error if the zone does not exist
			return nil, n.GetCNRApiError("Use `dnscontrol create-domains` to create not-existing zone", domain, r)
		}
		// Return general error for any other issues
		return nil, n.GetCNRApiError("Failed loading resource records for zone", domain, r)
	}

	// Fetch the necessary columns from the response
	nameColumn := r.GetColumn("name").GetData()
	typeColumn := r.GetColumn("type").GetData()
	contentColumn := r.GetColumn("content").GetData()
	ttlColumn := r.GetColumn("ttl").GetData()
	prioColumn := r.GetColumn("prio").GetData()

	// Ensure all required columns are available
	if nameColumn == nil || typeColumn == nil || contentColumn == nil {
		return nil, fmt.Errorf("failed getting necessary columns for domain: %s", domain)
	}

	// Get the total number of records
	totalRecords := len(nameColumn)

	// Iterate over each record
	for i := 0; i < totalRecords; i++ {
		name := nameColumn[i]
		recordType := typeColumn[i]
		content := contentColumn[i]
		ttlStr := ttlColumn[i]
		prioColumn := prioColumn[i]

		// Parse the TTL string to an unsigned integer
		ttl, err := strconv.ParseUint(ttlStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid TTL value for domain %s: %s", domain, ttlStr)
		}

		// Initialize a new CNRRecord
		record := &CNRRecord{
			DomainName: domain,
			Host:       name,
			Fqdn:       fmt.Sprintf("%s.%s.", name, domain),
			Type:       recordType,
			TTL:        uint32(ttl),
		}

		// Update FQDN if the host is not "@"
		if record.Host != "@" {
			record.Fqdn = fmt.Sprintf("%s.%s", name, record.Fqdn)
		} else {
			record.Fqdn = fmt.Sprintf("%s.", name)
		}

		// Handle MX and SRV records which have priority
		if recordType == "MX" || recordType == "SRV" {
			if prioColumn != "" {
				prio, err := strconv.ParseUint(prioColumn, 10, 32)
				if err != nil {
					return nil, fmt.Errorf("invalid priority value for domain %s: %s", domain, prioColumn)
				}
				record.Priority = uint32(prio)
			}
			record.Answer = content
		} else {
			// For other record types, the answer is just the content
			record.Answer = content
		}

		// Append the record to the records slice
		records = append(records, record)
	}

	// Return the slice of records
	return records, nil
}

func (n *CNRClient) createRecordString(rc *models.RecordConfig, domain string) (string, error) {
	record := &CNRRecord{
		DomainName: domain,
		Host:       rc.GetLabel(),
		Type:       rc.Type,
		Answer:     rc.GetTargetField(),
		TTL:        rc.TTL,
		Priority:   uint32(rc.MxPreference),
	}
	switch rc.Type { // #rtype_variations
	case "A", "AAAA", "ANAME", "CNAME", "MX", "NS", "PTR":
		// nothing
	case "TLSA":
		record.Answer = fmt.Sprintf(`%v %v %v %s`, rc.TlsaUsage, rc.TlsaSelector, rc.TlsaMatchingType, rc.GetTargetField())
	case "CAA":
		record.Answer = fmt.Sprintf(`%v %s "%s"`, rc.CaaFlag, rc.CaaTag, record.Answer)
	case "TXT":
		record.Answer = txtutil.EncodeQuoted(rc.GetTargetTXTJoined())
	case "SRV":
		if rc.GetTargetField() == "." {
			return "", fmt.Errorf("SRV records with empty targets are not supported (as of 2020-02-27, the API returns 'Invalid attribute value syntax')")
		}
		record.Answer = fmt.Sprintf("%d %d %v", rc.SrvWeight, rc.SrvPort, record.Answer)
		record.Priority = uint32(rc.SrvPriority)
	default:
		panic(fmt.Sprintf("createRecordString rtype %v unimplemented", rc.Type))
		// We panic so that we quickly find any switch statements
		// that have not been updated for a new RR type.
	}

	str := record.Host + " " + fmt.Sprint(record.TTL) + " IN " + record.Type + " "
	if record.Type == "MX" || record.Type == "SRV" {
		str += fmt.Sprint(record.Priority) + " "
	}
	str += record.Answer
	return str, nil
}

// deleteRecordString constructs the record string based on the provided CNRRecord.
func (n *CNRClient) deleteRecordString(record *CNRRecord) string {
	values := []interface{}{
		record.Host,
		record.TTL,
		"IN",
		record.Type,
		record.Answer,
	}
	if record.Type == "NS" {
		values = append(values[:2], values[3:]...)
	}
	return fmt.Sprintf("%v %v %v %v %v", values...)
}
