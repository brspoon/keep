# Maintenance helper retirement

Keep 2.27.0 removes the host maintenance helper and the in-app **Install update**
and **Restart** controls. **Admin → About**
still checks for releases and links to the [manual Docker upgrade guide](MIGRATION.md#upgrade-an-installation).
New installations do not need helper enrollment or a host service.

Before upgrading an earlier enrolled installation, finish or recover its current
operation using the installed release and its original recovery procedures.
A queued, claimed, running, or held request, a closed maintenance barrier, or an
unresolved host operation is a reason to hold the upgrade. Do not manually restart
both containers in the middle of an operation or stop its helper before its
recovery is resolved. If its state is corrupt or cannot be reconciled, preserve
that evidence and the matching recovery point for investigation.

Once the helper is idle and the completed operation has reopened normal app
access, stop and disable its configured worker before changing the app image.
For the user service from the earlier Linux guide, inspect the unit first and
then run as its enrolled user:

```sh
systemctl --user status keep-maintenance.service
systemctl --user cat keep-maintenance.service
systemctl --user disable --now keep-maintenance.service
systemctl --user is-active keep-maintenance.service
```

Use the actual service name or supervisor configuration if yours differs.
Confirm the worker has stopped and cannot restart during the upgrade. Keep does
not stop or remove an existing host service for you.

Preserve the data volume's `/app/data/.maintenance` directory, the installation's
`.maintenance-host` directory, enrollment keys, request journals, deployment
configuration, database backups, and recovery image records. Keep the prior image
and the complete matched recovery point until the upgrade is verified. The new
app checks legacy maintenance state before changing database schemas and refuses
startup when an operation remains unresolved or its records are unsafe or
inconsistent. It does not delete those records or run the old helper.

Do not erase maintenance state, replace a corrupt record, or remove a pending
request to bypass the startup hold. A stopped host worker alone does not establish
that the app's recovery state is safe. Finish recovery with the previous release,
then retry the manual upgrade with the original owner, configuration, and data.
Use the [backup and restore guide](PORTABLE_BACKUP.md) to protect the recovery point.
