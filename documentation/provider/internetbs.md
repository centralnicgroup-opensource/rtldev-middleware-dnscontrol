DNSControl's Internet.bs provider supports being a Registrar. Support for being a DNS Provider is not included, but could be added in the future.

## Configuration

To use this provider, add an entry to `creds.json` with `TYPE` set to `INTERNETBS`
along with an API key and account password.

Example:

{% code title="creds.json" %}
```json
{
  "internetbs": {
    "TYPE": "INTERNETBS",
    "api-key": "your-api-key",
    "password": "account-password"
  }
}
```
{% endcode %}

## Metadata
This provider does not recognize any special metadata fields unique to Internet.bs.

## Usage
An example configuration:

{% code title="dnsconfig.js" %}
```javascript
var REG_INTERNETBS = NewRegistrar("internetbs");

D("example.com", REG_INTERNETBS,
  NAMESERVER("ns1.example.com."),
  NAMESERVER("ns2.example.com."),
END);
```
{% endcode %}

## Activation

Pay attention, you need to define white list of IP for API. But you always can change it on `My Profile > Reseller Settings`
