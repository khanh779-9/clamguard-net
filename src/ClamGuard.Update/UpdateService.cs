using ClamGuard.Core;

namespace ClamGuard.Update;

public sealed class UpdateService
{
    private readonly DatabaseUpdater _updater;
    public UpdateService(DatabaseUpdater updater) => _updater = updater;

    public Task<UpdateResult> UpdateAsync(string databaseDirectory, CancellationToken cancellationToken = default)
        => _updater.UpdateCvdAsync(databaseDirectory, "daily.cvd", cancellationToken);

    public Task ApplyCdiffAsync(string databaseDirectory, string patchFile, CancellationToken cancellationToken = default)
        => _updater.ApplyCdiffAsync(databaseDirectory, patchFile, cancellationToken);
}
