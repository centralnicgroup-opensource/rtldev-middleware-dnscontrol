package cloudns

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/diff"
	"github.com/StackExchange/dnscontrol/v4/providers"
	"github.com/miekg/dns/dnsutil"
	"golang.org/x/time/rate"
)

/*
ClouDNS API DNS provider:
Info required in `creds.json`:
   - auth-id or sub-auth-id
   - auth-password
*/

// NewCloudns creates the provider.
func NewCloudns(m map[string]string, metadata json.RawMessage) (providers.DNSServiceProvider, error) {
	c := &cloudnsProvider{}
	c.requestLimit = rate.NewLimiter(10, 10)

	c.creds.id, c.creds.password, c.creds.subid = m["auth-id"], m["auth-password"], m["sub-auth-id"]

	if (c.creds.id == "" && c.creds.subid == "") || c.creds.password == "" {
		return nil, errors.New("missing ClouDNS auth-id or sub-auth-id and auth-password")
	}

	return c, nil
}

var features = providers.DocumentationNotes{
	// The default for unlisted capabilities is 'Cannot'.
	// See providers/capabilities.go for the entire list of capabilities.
	providers.CanAutoDNSSEC:          providers.Can(),
	providers.CanGetZones:            providers.Can(),
	providers.CanConcur:              providers.Can(),
	providers.CanUseAlias:            providers.Can(),
	providers.CanUseCAA:              providers.Can(),
	providers.CanUseDNAME:            providers.Can(),
	providers.CanUseDSForChildren:    providers.Can(),
	providers.CanUseLOC:              providers.Can(),
	providers.CanUsePTR:              providers.Can(),
	providers.CanUseSRV:              providers.Can(),
	providers.CanUseSSHFP:            providers.Can(),
	providers.CanUseTLSA:             providers.Can(),
	providers.DocCreateDomains:       providers.Can(),
	providers.DocDualHost:            providers.Unimplemented(),
	providers.DocOfficiallySupported: providers.Cannot(),
}

func init() {
	const providerName = "CLOUDNS"
	const providerMaintainer = "@pragmaton"
	fns := providers.DspFuncs{
		Initializer:   NewCloudns,
		RecordAuditor: AuditRecords,
	}
	providers.RegisterDomainServiceProviderType(providerName, fns, features)
	providers.RegisterCustomRecordType("CLOUDNS_WR", providerName, "")
	providers.RegisterMaintainer(providerName, providerMaintainer)
}

// GetNameservers returns the nameservers for a domain.
func (c *cloudnsProvider) GetNameservers(domain string) ([]*models.Nameserver, error) {
	names, err := c.fetchAvailableNameservers()
	if err != nil {
		return nil, err
	}

	return models.ToNameservers(names)
}

// // GetDomainCorrections returns the corrections for a domain.
// func (c *cloudnsProvider) GetDomainCorrections(dc *models.DomainConfig) ([]*models.Correction, error) {
// 	dc, err := dc.Copy()
// 	if err != nil {
// 		return nil, err
// 	}

// 	dc.Punycode()

// 	if c.domainIndex == nil {
// 		if err := c.fetchDomainList(); err != nil {
// 			return nil, err
// 		}
// 	}
// 	_, ok := c.domainIndex[dc.Name]
// 	if !ok {
// 		return nil, fmt.Errorf("'%s' not a zone in ClouDNS account", dc.Name)
// 	}

// 	existingRecords, err := c.GetZoneRecords(dc.Name)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// Normalize
// 	models.PostProcessRecords(existingRecords)

// 	// Get a list of available TTL values.
// 	// The TTL list needs to be obtained for each domain, so get it first here.
// 	c.fetchAvailableTTLValues(dc.Name)
// 	// ClouDNS can only be specified from a specific TTL list, so change the TTL in advance.
// 	for _, record := range dc.Records {
// 		record.TTL = fixTTL(record.TTL)
// 	}

// 	return c.GetZoneRecordsCorrections(dc, existingRecords)
// }

// GetZoneRecordsCorrections returns a list of corrections that will turn existing records into dc.Records.
func (c *cloudnsProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, existingRecords models.Records) ([]*models.Correction, int, error) {
	domainID, ok, err := c.fetchDomainIndex(dc.Name)
	if err != nil {
		return nil, 0, err
	} else if !ok {
		return nil, 0, fmt.Errorf("'%s' not a zone in ClouDNS account", dc.Name)
	}

	// Get a list of available TTL values.
	// The TTL list needs to be obtained for each domain, so get it first here.
	allowedTTLValues, err := c.fetchAvailableTTLValues(dc.Name)
	if err != nil {
		return nil, 0, err
	}

	// ClouDNS can only be specified from a specific TTL list, so change the TTL in advance.
	for _, record := range dc.Records {
		record.TTL = fixTTL(allowedTTLValues, record.TTL)
	}

	dnssecFixes, err := c.getDNSSECCorrections(dc)
	if err != nil {
		return nil, 0, err
	}

	toReport, create, del, modify, actualChangeCount, err := diff.NewCompat(dc).IncrementalDiff(existingRecords)
	if err != nil {
		return nil, 0, err
	}
	// Start corrections with the reports
	corrections := diff.GenerateMessageCorrections(toReport)
	corrections = append(corrections, dnssecFixes...)

	// Deletes first so changing type works etc.
	for _, m := range del {
		id := m.Existing.Original.(*domainRecord).ID
		corr := &models.Correction{
			Msg: fmt.Sprintf("%s, ClouDNS ID: %s", m.String(), id),
			F: func() error {
				return c.deleteRecord(domainID, id)
			},
		}
		// at ClouDNS, we MUST have a NS for a DS
		// So, when deleting, we must delete the DS first, otherwise deleting the NS throws an error
		if m.Existing.Type == "DS" {
			// type DS is prepended - so executed first
			corrections = append([]*models.Correction{corr}, corrections...)
		} else {
			corrections = append(corrections, corr)
		}
	}

	var (
		createCorrections         []*models.Correction
		createARecordCorrections  []*models.Correction
		createNSRecordCorrections []*models.Correction
	)
	for _, m := range create {
		req, err := toReq(m.Desired)
		if err != nil {
			return nil, 0, err
		}

		// ClouDNS does not require the trailing period to be specified when creating an NS record where the A or AAAA record exists in the zone.
		// So, modify it to remove the trailing period.
		if req["record-type"] == "NS" && strings.HasSuffix(req["record"], domainID+".") {
			req["record"] = strings.TrimSuffix(req["record"], ".")
		}

		corr := &models.Correction{
			Msg: m.String(),
			F: func() error {
				return c.createRecord(domainID, req)
			},
		}
		// A & AAAA need to be created before NS #2244
		// NS need to be created before DS #1018
		// or else errors will be thrown
		switch m.Desired.Type {
		case "A", "AAAA":
			createARecordCorrections = append(createARecordCorrections, corr)
		case "NS":
			createNSRecordCorrections = append(createNSRecordCorrections, corr)
		default:
			createCorrections = append(createCorrections, corr)
		}
	}
	corrections = append(corrections, createARecordCorrections...)
	corrections = append(corrections, createNSRecordCorrections...)
	corrections = append(corrections, createCorrections...)

	for _, m := range modify {
		id := m.Existing.Original.(*domainRecord).ID
		req, err := toReq(m.Desired)
		if err != nil {
			return nil, 0, err
		}

		// ClouDNS does not require the trailing period to be specified when updating an NS record where the A or AAAA record exists in the zone.
		// So, modify it to remove the trailing period.
		if req["record-type"] == "NS" && strings.HasSuffix(req["record"], domainID+".") {
			req["record"] = strings.TrimSuffix(req["record"], ".")
		}

		corr := &models.Correction{
			Msg: fmt.Sprintf("%s, ClouDNS ID: %s: ", m.String(), id),
			F: func() error {
				return c.modifyRecord(domainID, id, req)
			},
		}
		corrections = append(corrections, corr)
	}

	return corrections, actualChangeCount, nil
}

// getDNSSECCorrections returns corrections that update a domain's DNSSEC state.
func (c *cloudnsProvider) getDNSSECCorrections(dc *models.DomainConfig) ([]*models.Correction, error) {
	enabled, err := c.isDnssecEnabled(dc.Name)
	if err != nil {
		return nil, err
	}

	if enabled && dc.AutoDNSSEC == "off" {
		return []*models.Correction{
			{
				Msg: "Disable DNSSEC",
				F:   func() error { err := c.setDnssec(dc.Name, false); return err },
			},
		}, nil
	}

	if !enabled && dc.AutoDNSSEC == "on" {
		return []*models.Correction{
			{
				Msg: "Enable DNSSEC",
				F:   func() error { err := c.setDnssec(dc.Name, true); return err },
			},
		}, nil
	}

	return []*models.Correction{}, nil
}

// GetZoneRecords gets the records of a zone and returns them in RecordConfig format.
func (c *cloudnsProvider) GetZoneRecords(domain string, meta map[string]string) (models.Records, error) {
	records, err := c.getRecords(domain)
	if err != nil {
		return nil, err
	}
	existingRecords := make([]*models.RecordConfig, len(records))
	for i := range records {
		existingRecords[i], err = toRc(domain, &records[i])
		if err != nil {
			return nil, err
		}
	}
	return existingRecords, nil
}

// EnsureZoneExists creates a zone if it does not exist
func (c *cloudnsProvider) EnsureZoneExists(domain string) error {
	if _, ok, err := c.fetchDomainIndex(domain); err != nil {
		return err
	} else if ok { // zone already exists
		return nil
	}
	return c.createDomain(domain)
}

// parses the ClouDNS format into our standard RecordConfig
func toRc(domain string, r *domainRecord) (*models.RecordConfig, error) {
	ttl, _ := strconv.ParseUint(r.TTL, 10, 32)
	priority, _ := strconv.ParseUint(r.Priority, 10, 16)
	weight, _ := strconv.ParseUint(r.Weight, 10, 16)
	port, _ := strconv.ParseUint(r.Port, 10, 16)

	rc := &models.RecordConfig{
		Type:         r.Type,
		TTL:          uint32(ttl),
		MxPreference: uint16(priority),
		SrvPriority:  uint16(priority),
		SrvWeight:    uint16(weight),
		SrvPort:      uint16(port),
		Original:     r,
	}
	rc.SetLabel(r.Host, domain)

	var err error
	switch rtype := r.Type; rtype { // #rtype_variations
	case "TXT":
		err = rc.SetTargetTXT(r.Target)
	case "CNAME", "DNAME", "MX", "NS", "SRV", "ALIAS", "PTR":
		if err := rc.SetTarget(dnsutil.AddOrigin(r.Target+".", domain)); err != nil {
			return nil, err
		}
	case "CAA":
		caaFlag, _ := strconv.ParseUint(r.CaaFlag, 10, 8)
		rc.CaaFlag = uint8(caaFlag)
		rc.CaaTag = r.CaaTag
		err = rc.SetTarget(r.CaaValue)
	case "TLSA":
		tlsaUsage, _ := strconv.ParseUint(r.TlsaUsage, 10, 8)
		rc.TlsaUsage = uint8(tlsaUsage)
		tlsaSelector, _ := strconv.ParseUint(r.TlsaSelector, 10, 8)
		rc.TlsaSelector = uint8(tlsaSelector)
		tlsaMatchingType, _ := strconv.ParseUint(r.TlsaMatchingType, 10, 8)
		rc.TlsaMatchingType = uint8(tlsaMatchingType)
		err = rc.SetTarget(r.Target)
	case "SSHFP":
		sshfpAlgorithm, _ := strconv.ParseUint(r.SshfpAlgorithm, 10, 8)
		rc.SshfpAlgorithm = uint8(sshfpAlgorithm)
		sshfpFingerprint, _ := strconv.ParseUint(r.SshfpFingerprint, 10, 8)
		rc.SshfpFingerprint = uint8(sshfpFingerprint)
		err = rc.SetTarget(r.Target)
	case "DS":
		dsKeyTag, _ := strconv.ParseUint(r.DsKeyTag, 10, 16)
		rc.DsKeyTag = uint16(dsKeyTag)
		dsAlgorithm, _ := strconv.ParseUint(r.SshfpAlgorithm, 10, 8) // SshFpAlgorithm and DsAlgorithm both use json field "algorithm"
		rc.DsAlgorithm = uint8(dsAlgorithm)
		dsDigestType, _ := strconv.ParseUint(r.DsDigestType, 10, 8)
		rc.DsDigestType = uint8(dsDigestType)
		rc.DsDigest = r.Target
		err = rc.SetTarget(r.Target)
	case "CLOUD_WR":
		rc.Type = "WR"
		err = rc.SetTarget(r.Target)
	case "LOC":
		loc := fmt.Sprintf("%s %s %s %s %s %s %s %s %s %s %s %s",
			r.LocLatDeg, r.LocLatMin, r.LocLatSec, r.LocLatDir,
			r.LocLongDeg, r.LocLongMin, r.LocLongSec, r.LocLongDir,
			r.LocAltitude, r.LocSize, r.LocHPrecision, r.LocVPrecision)
		err = rc.SetTargetLOCString(r.Target, loc)
	default:
		err = rc.SetTarget(r.Target)
	}

	return rc, err
}

func formatLocParam(param string) string {
	param = strings.Split(param, "m")[0]
	// API misbehaves with a parameter of "0.00" and treats it as the default, so convert to "0" for this case only
	if param == "0.00" {
		param = "0"
	}
	return param
}

// toReq takes a RecordConfig and turns it into the native format used by the API.
func toReq(rc *models.RecordConfig) (requestParams, error) {
	req := requestParams{
		"record-type": rc.Type,
		"host":        rc.GetLabel(),
		"record":      rc.GetTargetField(),
		"ttl":         strconv.Itoa(int(rc.TTL)),
	}

	// ClouDNS doesn't use "@", it uses an empty name
	if req["host"] == "@" {
		req["host"] = ""
	}

	switch rc.Type { // #rtype_variations
	case "A", "AAAA", "NS", "PTR", "TXT", "SOA", "ALIAS", "CNAME", "WR", "DNAME":
		// Nothing special.
	case "CLOUDNS_WR":
		req["record-type"] = "WR"
	case "MX":
		req["priority"] = strconv.Itoa(int(rc.MxPreference))
	case "SRV":
		req["priority"] = strconv.Itoa(int(rc.SrvPriority))
		req["weight"] = strconv.Itoa(int(rc.SrvWeight))
		req["port"] = strconv.Itoa(int(rc.SrvPort))
	case "CAA":
		req["caa_flag"] = strconv.Itoa(int(rc.CaaFlag))
		req["caa_type"] = rc.CaaTag
		req["caa_value"] = rc.GetTargetField()
	case "TLSA":
		req["tlsa_usage"] = strconv.Itoa(int(rc.TlsaUsage))
		req["tlsa_selector"] = strconv.Itoa(int(rc.TlsaSelector))
		req["tlsa_matching_type"] = strconv.Itoa(int(rc.TlsaMatchingType))
	case "SSHFP":
		req["algorithm"] = strconv.Itoa(int(rc.SshfpAlgorithm))
		req["fptype"] = strconv.Itoa(int(rc.SshfpFingerprint))
	case "DS":
		req["key-tag"] = strconv.Itoa(int(rc.DsKeyTag))
		req["algorithm"] = strconv.Itoa(int(rc.DsAlgorithm))
		req["digest-type"] = strconv.Itoa(int(rc.DsDigestType))
		req["record"] = rc.DsDigest
	case "LOC":
		parts := strings.Fields(rc.GetTargetCombined())
		req["lat-deg"] = parts[0]
		req["lat-min"] = parts[1]
		req["lat-sec"] = parts[2]
		req["lat-dir"] = parts[3]
		req["long-deg"] = parts[4]
		req["long-min"] = parts[5]
		req["long-sec"] = parts[6]
		req["long-dir"] = parts[7]
		req["altitude"] = formatLocParam(parts[8])
		req["size"] = formatLocParam(parts[9])
		req["h-precision"] = formatLocParam(parts[10])
		req["v-precision"] = formatLocParam(parts[11])
	default:
		return nil, fmt.Errorf("ClouDNS.toReq rtype %q unimplemented", rc.Type)
	}

	return req, nil
}
