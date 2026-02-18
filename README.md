Bug: every clients get the same data.

The `/api/v1/auth/me` is correct so the problem can be on the frontend

`this.cachedTenantId` does not delete when the user switch.

Maybe we need `this.cachedTenantId = null;` when the user logs out.