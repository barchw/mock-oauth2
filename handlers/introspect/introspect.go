package introspect

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"net/http"
)

const (
	active = "active"
	scope  = "scope"
)

type Handler struct {
	ReadToken    uuid.UUID
	NoScopeToken uuid.UUID
	JWK          jwk.Set
}

func NewHandler(readToken uuid.UUID, noScopeToken uuid.UUID) *Handler {
	return &Handler{ReadToken: readToken, NoScopeToken: noScopeToken}
}

func (h Handler) Handle(c *gin.Context) {
	token := c.PostForm("token")

	switch token {
	case h.ReadToken.String():
		c.JSON(http.StatusOK, gin.H{
			active: true,
			scope:  "read",
		})
	case h.NoScopeToken.String():
		c.JSON(http.StatusOK, gin.H{
			active: true,
		})
	default:
		parsedJWT, err := jwt.ParseForm(c.Request.PostForm, "token", jwt.WithVerify(false))
		if err != nil {
			c.Status(http.StatusUnauthorized)
			return
		}

		scp, ok := parsedJWT.Get("scope")
		if ok {
			c.JSON(http.StatusOK, gin.H{
				active: true,
				scope:  scp,
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				active: true,
			})
		}
	}
}
