# DESIGN-ko.md

[English](DESIGN.md) | 한국어

## 제품 아키타입 (Product archetype)

`archetype: Admin Console`

ldapium은 LDAP 디렉토리 서비스를 위한 관리자 콘솔 및 계정 관리 인터페이스를 제공합니다.

## 제품 성격 (Personality)

- **밀도 (Density):** 높음 (High — 트리 탐색 및 대량 속성 편집을 위한 컴팩트 데이터 레이아웃)
- **시각적 비중:** 절제된 관리자 테마 및 고대비 상태 배지
- **강조 색상:** 기본 브랜드 블루 (`#2563eb`) 및 위험 작업에 대한 명확한 상태 구분

## 시맨틱 토큰 매핑 (Token mapping)

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
