using System.Security.Cryptography;
using AwesomeAssertions;
using RunOrNope.Analyzers.Msi;
using RunOrNope.Tests.Msi;
using Xunit;

namespace RunOrNope.SecurityTests.Msi;

public sealed class MsiReadOnlyTests
{
    [Fact]
    public void Inventory_preserves_hash_and_releases_file_for_exclusive_open()
    {
        using var fixture = new MsiFixtureBuilder()
            .AddTable("CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) PRIMARY KEY `Property`)")
            .Insert("INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)", "ProductName", "Benign Fixture");
        var path = fixture.Commit();
        var before = SHA256.HashData(File.ReadAllBytes(path));

        using (var database = MsiDatabase.OpenReadOnly(path))
        {
            database.Query(
                MsiTables.Property,
                [],
                MsiAnalysisLimits.Default,
                TestContext.Current.CancellationToken).Single()
                .Fields[1].Text!.DisplayText.Should().Be("Benign Fixture");
        }

        byte[] after;
        using (var exclusive = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            after = SHA256.HashData(exclusive);
        }
        after.Should().Equal(before);
    }

    [Fact]
    public void Production_metadata_contains_none_of_the_fixture_write_imports()
    {
        var prohibited = new[]
        {
            "MsiAdvertiseProductW",
            "MsiApplyPatchW",
            "MsiApplyTransformW",
            "MsiConfigureProductW",
            "MsiCreateRecord",
            "MsiDatabaseCommit",
            "MsiInstallProductW",
            "MsiOpenPackageW",
            "MsiOpenProductW",
            "MsiRecordSetInteger",
            "MsiRecordSetStreamW",
            "MsiRecordSetStringW",
            "MsiSummaryInfoPersist",
            "MsiSummaryInfoSetPropertyW",
            "MsiViewModify",
        };
        var imported = typeof(MsiDatabase).Assembly.GetTypes()
            .SelectMany(type => type.GetMethods(
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic))
            .Where(method => method.GetCustomAttributes(typeof(System.Runtime.InteropServices.DllImportAttribute), false).Length != 0)
            .Select(method => method.Name);

        imported.Should().NotContain(prohibited);
    }
}
