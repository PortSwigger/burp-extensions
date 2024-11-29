package burp;

import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Utilities
{
    static byte[] getAppropriateRequest(IExtensionHelpers helpers, byte[] request)
    {
        if ("GET".equals(helpers.analyzeRequest(request).getMethod()))
        {
            request = helpers.toggleRequestMethod(request);
        }

        return request;
    }

    static String extractBodyFromRequest(IRequestInfo requestInfo, byte[] request)
    {
        int bodyOffset = requestInfo.getBodyOffset();

        return new String(request, bodyOffset, request.length - bodyOffset, UTF_8);
    }

    static Map<String, String> splitQuery(String body)
    {
        Map<String, String> query_pairs = new LinkedHashMap<>();
        String[] pairs = body.split("&");

        for (String pair : pairs)
        {
            final int idx = pair.indexOf("=");
            final String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), UTF_8) : pair;
            if (!query_pairs.containsKey(key))
            {
                query_pairs.put(key, "");
            }
            final String value = idx > 0 && pair.length() > idx + 1 ? URLDecoder.decode(pair.substring(idx + 1), UTF_8) : "";
            query_pairs.put(key, value.trim());
        }
        return query_pairs;
    }
}
