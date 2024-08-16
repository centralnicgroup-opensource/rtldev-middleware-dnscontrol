package centralnicreseller

import (
	"fmt"

	"github.com/centralnicgroup-opensource/rtldev-middleware-go-sdk/v3/response"
)

// GetCNRApiError returns an error including API error code and error description.
func (n *HXClient) GetCNRApiError(format string, objectid string, r *response.Response) error {
	return fmt.Errorf(format+" %q. [%v %s]", objectid, r.GetCode(), r.GetDescription())
}
