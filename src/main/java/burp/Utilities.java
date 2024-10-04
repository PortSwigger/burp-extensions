package burp;

import com.google.gson.Gson;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.json.XML;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Utilities
{

    public static byte[] convertToXML(IExtensionHelpers helpers, IHttpRequestResponse requestResponse) throws Exception
    {
        byte[] request = requestResponse.getRequest();

        if (Objects.equals(helpers.analyzeRequest(request).getMethod(), "GET"))
        {
            request = helpers.toggleRequestMethod(request);
        }

        IRequestInfo requestInfo = helpers.analyzeRequest(request);

        int bodyOffset = requestInfo.getBodyOffset();

        byte content_type = requestInfo.getContentType();

        String body = new String(request, bodyOffset, request.length - bodyOffset, UTF_8);

        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>");
        xml.append("<root>");

        if (content_type == 0 || content_type == 1)
        {
            Map<String, String> params = splitQuery(body);
            Gson gson = new Gson();
            body = gson.toJson(params);
        }

        Document doc;

        try
        {
            Object json = new JSONTokener(body).nextValue();

            xml.append(XML.toString(json));
            xml.append("</root>");

            ByteArrayInputStream input = new ByteArrayInputStream(xml.toString().getBytes(UTF_8));

            DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            doc = builder.parse(input);

        }
        catch (Exception e)
        {
            return null; //TODO
        }

        List<String> headers = helpers.analyzeRequest(request).getHeaders();
        headers.removeIf(s -> s.contains("Content-Type"));
        headers.add("Content-Type: application/xml;charset=UTF-8");

        return helpers.buildHttpMessage(headers, prettyPrint(doc).getBytes());
    }

    public static byte[] convertToJSON(IExtensionHelpers helpers, IHttpRequestResponse requestResponse)
    {

        byte[] request = requestResponse.getRequest();

        if (Objects.equals(helpers.analyzeRequest(request).getMethod(), "GET"))
        {
            request = helpers.toggleRequestMethod(request);
        }

        IRequestInfo requestInfo = helpers.analyzeRequest(request);

        int bodyOffset = requestInfo.getBodyOffset();

        byte content_type = requestInfo.getContentType();

        String body = new String(request, bodyOffset, request.length - bodyOffset);

        String json;

        try
        {
            if (content_type == 3)
            {
                JSONObject xmlJSONObject = XML.toJSONObject(body);
                json = xmlJSONObject.toString(2);
            }
            else if (content_type == 0 || content_type == 1)
            {
                Map<String, String> params = splitQuery(body);
                Gson gson = new Gson();
                json = gson.toJson(params);
            }
            else
            {
                json = body;
            }
        }
        catch (Exception e)
        {
            return request;
        }

        List<String> headers = helpers.analyzeRequest(request).getHeaders();
        headers.removeIf(s -> s.contains("Content-Type"));
        headers.add("Content-Type: application/json;charset=UTF-8");

        return helpers.buildHttpMessage(headers, json.getBytes());
    }

    private static Map<String, String> splitQuery(String body)
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

    private static String prettyPrint(Document xml) throws Exception
    {
        Transformer tf = TransformerFactory.newInstance().newTransformer();
        tf.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        tf.setOutputProperty(OutputKeys.INDENT, "yes");
        Writer out = new StringWriter();
        tf.transform(new DOMSource(xml), new StreamResult(out));
        return (out.toString());
    }
}
