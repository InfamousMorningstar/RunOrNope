using System.Runtime.CompilerServices;

// The broker borrows the validated handle to launch a worker. Named-assembly friendship
// is not a security boundary — these assemblies are not strong-named, so anything that
// can place a DLL named RunOrNope.Broker.Windows beside the app can see these internals.
// That attacker already controls the process; the point of the restriction is to keep the
// presentation layer from acquiring an ownership-bearing handle by accident.
[assembly: InternalsVisibleTo("RunOrNope.Broker.Windows")]
[assembly: InternalsVisibleTo("RunOrNope.UnitTests")]
[assembly: InternalsVisibleTo("RunOrNope.IntegrationTests")]
[assembly: InternalsVisibleTo("RunOrNope.SecurityTests")]
