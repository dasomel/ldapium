# DESIGN.md

English | [한국어](DESIGN-ko.md)

## Product archetype

`archetype: Admin Console`

ldapium provides an administrative console and directory management interface for LDAP services.

## Product personality

- **Density:** High (compact data density for tree browsing and bulk attribute management)
- **Visual weight:** Restrained administrative theme with high-contrast status badges
- **Accent:** Primary brand blue (`#2563eb`) with clear operational distinction for destructive actions

## Token mapping

```yaml
tokens:
  bgCanvas: var(--of-color-bg-canvas, #0f172a)
  bgSurface: var(--of-color-bg-surface, #1e293b)
  bgSurfaceRaised: var(--of-color-bg-surface-raised, #334155)
  textPrimary: var(--of-color-text-primary, #f8fafc)
  textSecondary: var(--of-color-text-secondary, #94a3b8)
  textMuted: var(--of-color-text-muted, #64748b)
  borderDefault: var(--of-color-border-default, #334155)
  accentPrimary: var(--of-color-accent-primary, #3b82f6)
  danger: var(--of-color-status-danger, #ef4444)
  success: var(--of-color-status-success, #22c55e)
```

## Architecture and UI Boundaries

- Tree browsing and attribute editing maintain directory-level schema safety.
- Batch operations require explicit confirmation dialogs.
- Destructive modifications (delete subtree, reset password) use danger semantics.
