package fedentities

import (
	"slices"

	"github.com/gofiber/fiber/v2"

	"github.com/zachmann/go-oidfed/pkg"
	"github.com/zachmann/go-oidfed/pkg/fedentities/storage"
)

// AddTrustMarkedEntitiesListingEndpoint adds a trust marked entities endpoint
func (fed *FedEntity) AddTrustMarkedEntitiesListingEndpoint(
	endpoint EndpointConf,
	store storage.TrustMarkedEntitiesStorageBackend,
) {
	fed.Metadata.FederationEntity.FederationTrustMarkListEndpoint = endpoint.ValidateURL(fed.FederationEntity.EntityID)
	if endpoint.Path == "" {
		return
	}
	fed.server.Get(
		endpoint.Path, func(ctx *fiber.Ctx) error {
			trustMarkID := ctx.Query("trust_mark_id")
			sub := ctx.Query("sub")
			if trustMarkID == "" {
				ctx.Status(fiber.StatusBadRequest)
				return ctx.JSON(
					pkg.ErrorInvalidRequest(
						"required parameter 'trust_mark_id' not given",
					),
				)
			}
			if !slices.Contains(
				fed.TrustMarkIssuer.TrustMarkIDs(),
				trustMarkID,
			) {
				ctx.Status(fiber.StatusNotFound)
				return ctx.JSON(
					pkg.ErrorNotFound("'trust_mark_id' not known"),
				)
			}
			entities := make([]string, 0)
			var err error
			if sub != "" {
				hasTM, err := store.HasTrustMark(trustMarkID, sub)
				if err != nil {
					ctx.Status(fiber.StatusInternalServerError)
					return ctx.JSON(pkg.ErrorServerError(err.Error()))
				}
				if hasTM {
					entities = []string{sub}
				}
			} else {
				entities, err = store.Active(trustMarkID)
				if err != nil {
					ctx.Status(fiber.StatusInternalServerError)
					return ctx.JSON(pkg.ErrorServerError(err.Error()))
				}
				if len(entities) == 0 {
					entities = make([]string, 0)
				}
			}
			return ctx.JSON(entities)
		},
	)
}
