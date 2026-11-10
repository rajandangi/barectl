# Operator accounts

The [local setup](../README.md#run-locally) creates the first operator account with `createsuperuser`. Barectl has no public registration, email password reset or Django admin. Use **Settings > Your account** to change your password while signed in. To reset a forgotten password, run this on the controller host:

```bash
uv run --env-file .env python manage.py changepassword <username>
```

The initial migrations create the **Viewer**, **Site operator** and **Administrator** groups. Assign a preset from the controller host's Django shell:

```python
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

user = get_user_model().objects.get(username="operator")
user.groups.add(Group.objects.get(name="Site operator"))
```

| Preset | Permissions | Allows |
| --- | --- | --- |
| Viewer | `servers.view_server`, `operations.view_changes` | Servers, reviews and runs |
| Site operator | The above and `operations.change_site` | Preparing any change, and applying Site changes such as a site's PHP or Node selection |
| Administrator | The above and `operations.change_shared`, `operations.change_destructive`, `operations.manage_secrets` | Applying Shared changes such as Set up server, Add runtime, server defaults and site creation beside other sites |

The superuser has every permission. Registering, editing and removing servers need `servers.add_server`, `servers.change_server` and `servers.delete_server`, starting a connection check needs `discovery.add_discoveryattempt`, and seeing sites needs `discovery.view_siteobservation`; the presets grant none of these. Barectl has no interface for granting permissions. Inventory is shared among authorized operators; organization isolation is not implemented.
