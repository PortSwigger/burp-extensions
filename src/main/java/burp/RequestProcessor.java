package burp;

import java.util.List;

import static burp.Utilities.extractBodyFromRequest;
import static burp.Utilities.getAppropriateRequest;

public class RequestProcessor
{
    private final IExtensionHelpers helpers;
    private final BodyProcessor bodyProcessor;
    private final String contentTypeHeaderValue;

    public RequestProcessor(IExtensionHelpers helpers, BodyProcessor bodyProcessor, String contentTypeHeaderValue)
    {
        this.helpers = helpers;
        this.bodyProcessor = bodyProcessor;
        this.contentTypeHeaderValue = contentTypeHeaderValue;
    }

    public byte[] convert(byte[] initialRequest)
    {
        byte[] request = getAppropriateRequest(helpers, initialRequest);

        IRequestInfo requestInfo = helpers.analyzeRequest(request);

        byte contentType = requestInfo.getContentType();
        String body = extractBodyFromRequest(requestInfo, request);

        String processedBody = bodyProcessor.process(contentType, body);

        List<String> headers = helpers.analyzeRequest(request).getHeaders();
        headers.removeIf(s -> s.contains("Content-Type"));
        headers.add("Content-Type: " + contentTypeHeaderValue);

        return helpers.buildHttpMessage(headers, processedBody.getBytes());
    }
}
