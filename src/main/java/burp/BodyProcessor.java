package burp;

import com.google.gson.Gson;
import org.json.JSONTokener;
import org.json.XML;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Map;

import static burp.Utilities.splitQuery;
import static java.nio.charset.StandardCharsets.UTF_8;

public interface BodyProcessor
{
    String process(byte contentType, String body);

    class JsonBodyProcessor implements BodyProcessor
    {
        @Override
        public String process(byte contentType, String body)
        {
            return switch (contentType)
            {
                case 0, 1 -> new Gson().toJson(splitQuery(body));

                case 3 -> XML.toJSONObject(body).toString(2);

                default -> body;
            };
        }
    }

    class XmlBodyProcessor implements BodyProcessor
    {
        @Override
        public String process(byte contentType, String body)
        {
            if (contentType == 0 || contentType == 1)
            {
                Map<String, String> params = splitQuery(body);
                Gson gson = new Gson();
                body = gson.toJson(params);
            }

            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>");
            stringBuilder.append("<root>");

            try
            {
                Object json = new JSONTokener(body).nextValue();

                stringBuilder.append(XML.toString(json));
                stringBuilder.append("</root>");

                ByteArrayInputStream input = new ByteArrayInputStream(stringBuilder.toString().getBytes(UTF_8));

                DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
                Document doc = builder.parse(input);

                 return prettyPrint(doc);
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);
            }
        }

        private static String prettyPrint(Document xml)
        {
            try {
                Transformer tf = TransformerFactory.newInstance().newTransformer();
                tf.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
                tf.setOutputProperty(OutputKeys.INDENT, "yes");
                Writer out = new StringWriter();
                tf.transform(new DOMSource(xml), new StreamResult(out));

                return (out.toString());
            }
            catch (TransformerException e)
            {
                throw new RuntimeException(e);
            }
        }
    }
}
