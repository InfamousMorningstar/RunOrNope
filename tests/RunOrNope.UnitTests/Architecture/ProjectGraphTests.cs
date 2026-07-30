using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using AwesomeAssertions;
using Xunit;

namespace RunOrNope.UnitTests.Architecture;

public sealed class ProjectGraphTests
{
    [Fact]
    public void Wpf_project_must_not_reference_parser_projects()
    {
        ProjectGraph.Load("RunOrNope.slnx")
            .ReferencesFrom("RunOrNope.App")
            .Should().NotContain(name => name.Contains("Analyzers", StringComparison.Ordinal));
    }

    [Fact]
    public void Msi_analyzer_must_reference_only_contracts_and_content() =>
        ProjectGraph.Load("RunOrNope.slnx")
            .ReferencesFrom("RunOrNope.Analyzers.Msi")
            .Should().BeEquivalentTo(
                "RunOrNope.Contracts",
                "RunOrNope.Analyzers.Content");

    [Fact]
    public void Repository_restores_must_use_locked_mode_by_default()
    {
        var properties = XDocument.Load(RepositoryFiles.PathTo("Directory.Build.props"));

        properties.Descendants("RestoreLockedMode")
            .Single().Value
            .Should().Be("true");
    }

    [Fact]
    public void Readme_must_publish_an_explicit_windows_build_matrix()
    {
        var readme = File.ReadAllText(RepositoryFiles.PathTo("README.md"));

        readme.Should().Contain("10.0.19041");
        readme.Should().Contain("Windows 11 Pro | 26200 | Locally validated");
        readme.Should().Contain("Windows 10 Enterprise LTSC 2021 | 19044 | Release-gating target");
        readme.Should().Contain("Windows 11 Enterprise 24H2 | 26100 | Release-gating target");
        readme.Should().Contain("All other Windows editions and builds | Any | Unverified");
        readme.Should().NotContain("- Windows 10 or Windows 11 on x64");
    }
}

internal sealed class ProjectGraph
{
    private readonly string _repositoryRoot;
    private readonly IReadOnlyDictionary<string, string> _projects;

    private ProjectGraph(string repositoryRoot, IReadOnlyDictionary<string, string> projects)
    {
        _repositoryRoot = repositoryRoot;
        _projects = projects;
    }

    public static ProjectGraph Load(string solutionPath)
    {
        var repositoryRoot = FindRepositoryRoot();
        var fullSolutionPath = Path.Combine(repositoryRoot, solutionPath);
        var document = XDocument.Load(fullSolutionPath);
        var projects = document.Descendants("Project")
            .Select(element => (string?)element.Attribute("Path"))
            .OfType<string>()
            .ToDictionary(
                path => Path.GetFileNameWithoutExtension(path),
                path => path,
                StringComparer.Ordinal);

        return new ProjectGraph(repositoryRoot, projects);
    }

    public IEnumerable<string> ReferencesFrom(string projectName)
    {
        var projectPath = Path.Combine(_repositoryRoot, _projects[projectName]);
        var document = XDocument.Load(projectPath);

        return document.Descendants("ProjectReference")
            .Select(element => (string?)element.Attribute("Include"))
            .OfType<string>()
            .Select(path => Path.GetFileNameWithoutExtension(path))
            .ToArray();
    }

    private static string FindRepositoryRoot()
    {
        return RepositoryFiles.Root;
    }
}

internal static class RepositoryFiles
{
    public static string Root { get; } = FindRepositoryRoot();

    public static string PathTo(string relativePath)
    {
        return Path.Combine(Root, relativePath);
    }

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory);
             directory is not null;
             directory = directory.Parent)
        {
            // In a linked worktree ".git" is a file holding a "gitdir:" pointer rather
            // than a directory, so a directory-only probe walks past the root and fails.
            var marker = Path.Combine(directory.FullName, ".git");
            if (Directory.Exists(marker) || File.Exists(marker))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("Could not locate the repository root.");
    }
}
