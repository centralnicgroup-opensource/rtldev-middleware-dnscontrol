// Code generated by "stringer -type=Capability"; DO NOT EDIT.

package providers

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[CanUseAlias-0]
	_ = x[CanUseCAA-1]
	_ = x[CanUsePTR-2]
	_ = x[CanUseNAPTR-3]
	_ = x[CanUseSRV-4]
	_ = x[CanUseSSHFP-5]
	_ = x[CanUseTLSA-6]
	_ = x[CanUseTXTMulti-7]
	_ = x[CanAutoDNSSEC-8]
	_ = x[CantUseNOPURGE-9]
	_ = x[DocOfficiallySupported-10]
	_ = x[DocDualHost-11]
	_ = x[DocCreateDomains-12]
	_ = x[CanUseRoute53Alias-13]
	_ = x[CanGetZones-14]
	_ = x[CanUseAzureAlias-15]
}

const _Capability_name = "CanUseAliasCanUseCAACanUsePTRCanUseNAPTRCanUseSRVCanUseSSHFPCanUseTLSACanUseTXTMultiCanAutoDNSSECCantUseNOPURGEDocOfficiallySupportedDocDualHostDocCreateDomainsCanUseRoute53AliasCanGetZonesCanUseAzureAlias"

var _Capability_index = [...]uint8{0, 11, 20, 29, 40, 49, 60, 70, 84, 97, 111, 133, 144, 160, 178, 189, 205}

func (i Capability) String() string {
	if i >= Capability(len(_Capability_index)-1) {
		return "Capability(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _Capability_name[_Capability_index[i]:_Capability_index[i+1]]
}