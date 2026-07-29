using System.Windows;

namespace RunOrNope.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        new MainWindow().Show();
    }
}
