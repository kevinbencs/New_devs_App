Bug: every clients get the same data.

The `/api/v1/auth/me` is correct so the problem can be on the frontend

{*`this.cachedTenantId` does not delete when the user switch.

Maybe we need `this.cachedTenantId = null;` when the user logs out.*/}



The problem is in the backend (`/api/v1/dashboard/summary`)

The `calculate_total_revenue(property_id, tenant_id)` returns bad data.

The error is database connection error:
`ERROR:app.core.database_pool:❌ Database pool initialization failed: 'Settings' object has no attribute 'supabase_db_user'
backend-1   | Traceback (most recent call last):
backend-1   |   File "/app/app/services/reservations.py", line 86, in calculate_total_revenue
backend-1   |     raise Exception("Database pool not available")
backend-1   | Exception: Database pool not available
backend-1   | Database error for prop-001 (tenant: tenant-b): Database pool not available
backend-1   | {'property_id': 'prop-001', 'tenant_id': 'tenant-b', 'total': '1000.00', 'currency': 'USD', 'count': 3}
backend-1   | id='user-ocean' email='ocean@propertyflow.com' permissions=[] cities=[] is_admin=False tenant_id='tenant-b'
`