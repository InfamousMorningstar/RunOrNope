using System.Net;
using System.Text;

namespace RunOrNope.Reporting;

internal static class SafeText
{
    internal static StringBuilder Append(StringBuilder builder, string? value) =>
        builder.Append(WebUtility.HtmlEncode(value ?? string.Empty));
}
