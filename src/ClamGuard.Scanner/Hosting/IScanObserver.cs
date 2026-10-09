using ClamGuard.Core;

namespace ClamGuard.Scanner.Hosting;

public interface IScanObserver
{
    void OnStarted(string path);
    void OnCompleted(ScanResult result);
    void OnRejected(string path, string reason);
}
