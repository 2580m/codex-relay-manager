using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

// Deliberately inert native-process fixture: never invokes Codex or an API.
public static class RelayArgvRecorder
{
    private static string Quote(string value)
    {
        if (value == null) return "null";
        var output = new StringBuilder("\"");
        foreach (char c in value)
        {
            switch (c)
            {
                case '\\': output.Append("\\\\"); break;
                case '"': output.Append("\\\""); break;
                case '\n': output.Append("\\n"); break;
                case '\r': output.Append("\\r"); break;
                case '\t': output.Append("\\t"); break;
                default:
                    if (c < 32) output.Append("\\u" + ((int)c).ToString("x4"));
                    else output.Append(c);
                    break;
            }
        }
        return output.Append('"').ToString();
    }
    public static int Main(string[] args)
    {
        string path = Environment.GetEnvironmentVariable("RELAY_TEST_RECORDER_PATH");
        if (String.IsNullOrEmpty(path)) return 12;
        var argv = new List<string>();
        foreach (string arg in args) argv.Add(Quote(arg));
        string keyName = Environment.GetEnvironmentVariable("RELAY_TEST_KEY_NAME");
        string keyValue = String.IsNullOrEmpty(keyName) ? null : Environment.GetEnvironmentVariable(keyName);
        string content = "{\"Arguments\":[" + String.Join(",", argv.ToArray()) + "],\"KeyName\":" + Quote(keyName) + ",\"KeyValue\":" + Quote(keyValue) + ",\"OpenAIKey\":" + Quote(Environment.GetEnvironmentVariable("OPENAI_API_KEY")) + "}";
        string temporary = path + ".writing";
        File.WriteAllText(temporary, content, new UTF8Encoding(false));
        File.Move(temporary, path);
        return 0;
    }
}
