using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using FluentAssertions;
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
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory);
             directory is not null;
             directory = directory.Parent)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, ".git")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("Could not locate the repository root.");
    }
}
