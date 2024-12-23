# Example TA/IA using go-oidfed library
This is an example Trust Anchor / Intermediate Authority / Trust Mark Issuer that uses the go-oidfed library from this repository.

It showcases how to easily set up an configurable federation entity.

The following is an example `config.yaml` file:

```yaml
server_port: 8765
entity_id: "https://go-ia.fedservice.lh"
authority_hints:
  - "https://trust-anchor.fedservice.lh/"
signing_key_file: "/data/signing.key"
organization_name: "GO oidc-fed Intermediate"
data_location: "/data/data"
human_readable_storage: true
metadata_policy_file: "/data/metadata-policy.json"
endpoints:
  fetch:
    path: "/fetch"
    url: "https://go-ia.fedservice.lh/fetch"
  list:
    path: "/list"
    url: "https://go-ia.fedservice.lh/list"
  resolve:
    path: "/resolve"
    url: "https://go-ia.fedservice.lh/resolve"
  trust_mark:
    path: "/trustmark"
    url: "https://go-ia.fedservice.lh/trustmark"
  trust_mark_status:
    path: "/trustmark/status"
    url: "https://go-ia.fedservice.lh/trustmark/status"
  trust_mark_list:
    path: "/trustmark/list"
    url: "https://go-ia.fedservice.lh/trustmark/list"
  enroll:
    path: "/enroll"
    url: "https://go-ia.fedservice.lh/enroll"
    checker:
        type: trust_mark
        config:
          trust_mark_id: https://go-ia.federservice.lh/tm/federation-member
          trust_anchors:
            - entity_id: https://go-ia.fedservice.lh
trust_mark_specs:
  - trust_mark_id: "https://go-ia.federservice.lh/tm/federation-member"
    lifetime: 86400
    extra_claim: "example"
    checker:
      type: none
trust_mark_issuers:
  "https://go-ia.federservice.lh/tm/federation-member":
    - "https://go-ia.fedservice.lh"
trust_marks:
  - id: "https://go-ia.federservice.lh/tm/federation-member"
    trust_mark: "eyJhbGciOiJFUzUxMiIsImtpZCI6IlpsSFBmQXJTRnFGdjNHRlh3ZUptbmFkZDI4YTM4X3plcEJybEZkWHdIaTQiLCJ0eXAiOiJ0cnVzdC1tYXJrK2p3dCJ9.eyJleHAiOj..."
  - id: "https://trust-anchor.federservice.lh/tm/federation-member"
    trust_mark: "eyJhbGciOiJFUzUxMiIsImtpZCI6InpFLTlhVlhJanJZOUcxVU0tYURQVkxVR1RkWmFuOTk0NlJJUWhraWFjUVkiLCJ0eXAiOiJ0cnVzdC1tYXJrK2p3dCJ9.eyJleHAiO..."
```

An example docker compose file to run multiple intermediate /
trust anchors and relying parties in a small example federation can be found 
at [examples/edugain-pilot](../edugain-pilot):

## Enrolling Entities

The TA/IA has a custom enrollment / onboarding endpoint that can be configured as all endpoints in the config file.
This endpoint is used to easily add entities to the federation. Entities can
also be manually added to the database (or with a simple command line
application).

The enrollment endpoint can also be guarded by so-called *entity checks* (for
more information about entity checks, see below). If the enroll endpoint is
enabled, but no checks defined, all entities can enroll.

### Enrollment Request

To enroll, the entity sends a `POST` request to the enroll endpoint with the following request parameter:
- `sub` REQUIRED: Its entity id
- `entity_type` RECOMMENDED: Its entity type

`entity_type` can be provided multiple times to pass multiple entity types.

The TA/IA will query the entities federation endpoint for its entity configuration and obtain the jwks from there and (if configured) performs the entity checks.

## Entity Checks
With the *entity checks* mechanism checks on an entity can be defined. The
One can define their own entity checks by implementing the `EntityChecker` interface and registering it through the `RegisterEntityChecker` function before loading the config file.

The following entity checks are already implemented and supported by this
library:
- `none`: Always forbids access
- `trust_mark`: Checks if the entity advertises a trust mark and verifies that it is valid
- `trust_path`: Checks if there is a valid trust path from the entity to the defined trust anchor
- `authority_hints`: Checks if the entity's `authority_hints` contains the defined entity id
- `entity_id`: Checks if the entity's `entity_id` is one of the defined ones
- `multiple_and`: Used to combine multiple `EntityChecker` using AND
- `multiple_or`: Used to combine multiple `EntityChecker` using OR

## Trust Mark Issuance
The issuance of trust marks boils down to "if you are on the list of entities
that can obtain this trust mark, we will issue the trust mark".
Therefore, our trust mark issuer implementation manages a list of entities that
can obtain each trust mark.

It is possible to use the entity checks mechanism to dynamically add entities to
that list. I.e. any `EntityChecker` can be used on the trust mark endpoint,
resulting in the following behavior of the trust mark issuer:
- If the subject entity is already in the list the trust mark is issued.
- If not, and no checks are defined, no trust mark is issued.
- If not, and checks are defined, the checks are evaluated.
- If the checks are positive, the entity is added to the list and a trust mark is issued.
- If the checks are negative, no trust mark is issued.

