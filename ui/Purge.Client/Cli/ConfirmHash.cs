using System.Security.Cryptography;
using System.Text;

namespace Purge.Client.Cli;

/// <summary>
/// The confirm hash <c>purge-engine exec --confirm</c> checks (crates/purge-exec/src/plan_in.rs
/// <c>selection_hash</c> / <c>confirm_hash</c>): the selection hash is SHA-256 over the selected candidate ids,
/// empty ids dropped, de-duplicated, sorted ordinally (UTF-16 code units) and joined with LF, as UTF-8; the
/// confirm hash is SHA-256 over the plan hash text followed by the selection hash text, both lower-case hex.
/// </summary>
public static class ConfirmHash
{
    public static string Selection(IEnumerable<string> ids)
    {
        var sorted = ids.Where(id => id.Length > 0).Distinct(StringComparer.Ordinal).ToList();
        sorted.Sort(StringComparer.Ordinal);
        return Sha256Hex(string.Join('\n', sorted));
    }

    public static string Confirm(string planHash, IEnumerable<string> ids) =>
        Sha256Hex(planHash.ToLowerInvariant() + Selection(ids));

    private static string Sha256Hex(string text) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
}
