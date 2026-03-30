# Generic Simple Example

This dataset is intentionally small and is kept separate from the DO-356A Appendix D sample.

## Scope

- 4 assets:
  - `EXT-LAPTOP`: external service laptop
  - `IF-MAINT`: shared maintenance interface
  - `SYS-CTRL`: internal control unit
  - `SYS-LOG`: internal event log store
- 3 edges:
  - laptop <-> maintenance interface
  - maintenance interface <-> control unit
  - control unit <-> event log store
- 1 threat point:
  - misuse of the service laptop over the maintenance port
- 2 traceability links:
  - one generic scenario link
  - one generic requirement link

## Why This Example Exists

- It is easier to explain than the DO-356A aviation scenario.
- It still exercises the main product flow:
  - graph loading
  - attack-path analysis
  - path persistence
  - compliance-link review

## How To Load It

- Frontend button: `Load Generic Demo`
- API: `POST /admin/seed/generic`
- CLI:

```bash
npm run seed:generic
```
