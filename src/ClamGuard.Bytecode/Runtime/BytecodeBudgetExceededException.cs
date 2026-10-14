using System;

namespace ClamGuard.Bytecode;

/// <summary>
/// Raised when a bytecode program exhausts its instruction or runtime budget.
/// Distinct from <see cref="OperationCanceledException"/> so the scanner can
/// skip the individual program instead of aborting the whole file scan.
/// </summary>
internal sealed class BytecodeBudgetExceededException : Exception
{
    public BytecodeBudgetExceededException(string message) : base(message)
    {
    }
}
