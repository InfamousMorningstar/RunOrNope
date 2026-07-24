using Microsoft.Win32.SafeHandles;
using RunOrNope.Intake;
using Xunit;

namespace RunOrNope.UnitTests.Intake;

public sealed class VerifiedPathWalkerTests
{
    [Fact]
    public void SimulatedRemoteAncestorReparseStopsBeforeFinalOpen()
    {
        var native = new FakeRelativeNative { MarkFirstChildReparse = true };
        Assert.Throws<IntakeRejectedException>(() =>
            VerifiedPathWalker.Open(@"C:\drop\remote-link\sample.exe", native));
        Assert.Equal(0, native.FinalOpenCount);
    }

    [Fact]
    public void AncestorIdentitySwapFailsClosed()
    {
        var native = new FakeRelativeNative { SwapRootIdentityAfterChildOpen = true };
        Assert.Throws<IntakeTamperedException>(() =>
            VerifiedPathWalker.Open(@"C:\drop\sample.exe", native));
        Assert.Equal(0, native.FinalOpenCount);
    }

    private sealed class FakeRelativeNative : IRelativePathNative
    {
        private readonly Dictionary<SafeFileHandle, FileSnapshot> _snapshots = [];
        private SafeFileHandle? _root;
        private int _rootReads;
        private int _nextHandle = 100;
        public bool MarkFirstChildReparse { get; init; }
        public bool SwapRootIdentityAfterChildOpen { get; init; }
        public int FinalOpenCount { get; private set; }

        public SafeFileHandle OpenRoot(string root)
        {
            _root = NewHandle(DirectorySnapshot(1));
            return _root;
        }

        public SafeFileHandle OpenRelativeDirectory(SafeFileHandle parent, string component)
        {
            var snapshot = DirectorySnapshot((ulong)_nextHandle);
            if (MarkFirstChildReparse)
                snapshot = snapshot with { Attributes = WindowsFileIdentity.FileAttributeReparsePoint };
            return NewHandle(snapshot);
        }

        public SafeFileHandle OpenRelativeFile(SafeFileHandle parent, string component)
        {
            FinalOpenCount++;
            return NewHandle(DirectorySnapshot((ulong)_nextHandle) with { IsDirectory = false });
        }

        public FileSnapshot ReadSnapshot(SafeFileHandle handle)
        {
            var snapshot = _snapshots[handle];
            if (handle == _root && SwapRootIdentityAfterChildOpen && ++_rootReads >= 3)
                return snapshot with { Identity = new FileIdentity(1, Guid.NewGuid()) };
            return snapshot;
        }

        public string GetFinalPath(SafeFileHandle handle) => @"\\?\C:\verified";

        private SafeFileHandle NewHandle(FileSnapshot snapshot)
        {
            var handle = new SafeFileHandle(new IntPtr(_nextHandle++), ownsHandle: false);
            _snapshots.Add(handle, snapshot);
            return handle;
        }

        private static FileSnapshot DirectorySnapshot(ulong id) =>
            new(new FileIdentity(1, GuidFrom(id)), 0, 1, 0, 0, true, false);

        private static Guid GuidFrom(ulong value)
        {
            var bytes = new byte[16];
            BitConverter.GetBytes(value).CopyTo(bytes, 0);
            return new Guid(bytes);
        }
    }
}
