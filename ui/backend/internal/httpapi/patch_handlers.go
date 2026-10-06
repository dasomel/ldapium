package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/validate"
)

// PATCH /api/users and /api/groups follow JSON Merge Patch (RFC 7396): a key
// that is absent is preserved, a string sets the attribute, null removes it.
// An empty string is rejected rather than guessed at (set-to-empty versus
// remove is ambiguous), and uid/password/unknown keys are rejected so a typo
// can never silently do nothing or something else. PUT keeps its historical
// "omitted optional field is erased" meaning untouched.

const maxPatchBody = 64 << 10

// mergePatchFields reads the request body as one JSON object and returns its
// raw members. Only application/json and application/merge-patch+json are
// accepted.
func mergePatchFields(c echo.Context) (map[string]json.RawMessage, error) {
	mt, _, err := mime.ParseMediaType(c.Request().Header.Get(echo.HeaderContentType))
	if err != nil || (mt != "application/json" && mt != "application/merge-patch+json") {
		return nil, echo.NewHTTPError(http.StatusUnsupportedMediaType, "Content-Type must be application/merge-patch+json or application/json")
	}
	dec := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, maxPatchBody))
	var fields map[string]json.RawMessage
	if err := dec.Decode(&fields); err != nil || fields == nil {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	return fields, nil
}

// patchValue decodes one member: null clears, a non-empty string sets, and
// everything else (empty string, number, object, ...) is a 400.
func patchValue(raw json.RawMessage) (*domain.PatchField, error) {
	if string(raw) == "null" {
		return &domain.PatchField{Clear: true}, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, errors.New("fields must be a string or null")
	}
	if s == "" {
		return nil, errors.New("use null to remove a field; an empty string is not allowed")
	}
	return &domain.PatchField{Value: s}, nil
}

// splitPatch pulls the target dn out of fields, decodes the members named in
// allowed into dst (one pointer per field name) and refuses anything else.
func splitPatch(fields map[string]json.RawMessage, dst map[string]**domain.PatchField) (string, error) {
	var dn string
	if raw, ok := fields["dn"]; ok {
		if err := json.Unmarshal(raw, &dn); err != nil {
			return "", errors.New("dn must be a string")
		}
		delete(fields, "dn")
	}
	if err := validate.DN(dn); err != nil {
		return "", err
	}
	if _, ok := fields["uid"]; ok {
		return "", errors.New("uid cannot be changed")
	}
	if _, ok := fields["password"]; ok {
		return "", errors.New("password cannot be patched; use POST /api/users/password")
	}
	for name, target := range dst {
		raw, ok := fields[name]
		if !ok {
			continue
		}
		v, err := patchValue(raw)
		if err != nil {
			return "", err
		}
		*target = v
		delete(fields, name)
	}
	if len(fields) > 0 {
		// The offending name is not echoed back.
		return "", errors.New("unknown field in patch")
	}
	return dn, nil
}

func parseUserPatch(fields map[string]json.RawMessage) (string, domain.UserPatch, error) {
	var p domain.UserPatch
	dn, err := splitPatch(fields, map[string]**domain.PatchField{
		"cn": &p.CN, "sn": &p.SN, "givenName": &p.GivenName, "mail": &p.Mail,
		"department": &p.Department, "organization": &p.Organization, "organizationalUnit": &p.OrganizationalUnit,
	})
	if err != nil {
		return "", p, err
	}
	if p.Empty() {
		return "", p, errors.New("patch must change at least one field")
	}
	if p.CN != nil {
		if p.CN.Clear {
			return "", p, errors.New("cn cannot be removed")
		}
		if err := validate.CN(p.CN.Value); err != nil {
			return "", p, err
		}
	}
	if p.SN != nil {
		if p.SN.Clear {
			return "", p, errors.New("sn cannot be removed")
		}
		if err := validate.CN(p.SN.Value); err != nil {
			return "", p, err
		}
	}
	if p.Mail != nil && !p.Mail.Clear {
		if err := validate.Email(p.Mail.Value); err != nil {
			return "", p, err
		}
	}
	return dn, p, nil
}

func parseGroupPatch(fields map[string]json.RawMessage) (string, domain.GroupPatch, error) {
	var p domain.GroupPatch
	dn, err := splitPatch(fields, map[string]**domain.PatchField{"cn": &p.CN, "description": &p.Description})
	if err != nil {
		return "", p, err
	}
	if p.Empty() {
		return "", p, errors.New("patch must change at least one field")
	}
	if p.CN != nil {
		if p.CN.Clear {
			return "", p, errors.New("cn cannot be removed")
		}
		if err := validate.CN(p.CN.Value); err != nil {
			return "", p, err
		}
	}
	return dn, p, nil
}

func (s *Server) handlePatchUser(c echo.Context) error {
	fields, err := mergePatchFields(c)
	if err != nil {
		return err
	}
	dn, patch, err := parseUserPatch(fields)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	ifMatch, err := ifMatchCSN(c)
	if err != nil {
		return err
	}
	if err := currentSession(c).Bound.PatchUser(c.Request().Context(), dn, patch, ifMatch); err != nil {
		return respondErr(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (s *Server) handlePatchGroup(c echo.Context) error {
	fields, err := mergePatchFields(c)
	if err != nil {
		return err
	}
	dn, patch, err := parseGroupPatch(fields)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	ifMatch, err := ifMatchCSN(c)
	if err != nil {
		return err
	}
	if err := currentSession(c).Bound.PatchGroup(c.Request().Context(), dn, patch, ifMatch); err != nil {
		return respondErr(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}
