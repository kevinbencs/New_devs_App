Bug: every clients get the same data.

The `/api/v1/auth/me` is correct so the problem can be on the frontend

{*`this.cachedTenantId` does not delete when the user switch.

Maybe we need `this.cachedTenantId = null;` when the user logs out.*/}



The problem is in the backend (`/api/v1/dashboard/summary`)

The `calculate_total_revenue(property_id, tenant_id)` returns bad data.

