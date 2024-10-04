package burp;

import javax.swing.*;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import static burp.IBurpExtenderCallbacks.TOOL_INTRUDER;
import static burp.IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST;

public class Menu implements IContextMenuFactory
{
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;

    public Menu(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation)
    {
        List<JMenuItem> menus = new ArrayList<>();

        if (invocation.getToolFlag() != TOOL_INTRUDER && invocation.getInvocationContext() != CONTEXT_MESSAGE_EDITOR_REQUEST)
        {
            return menus;
        }

        JMenuItem sendXMLToRepeater = new JMenuItem("Convert to XML");
        sendXMLToRepeater.addActionListener(l -> {
            IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];

            try
            {
                byte[] request = Utilities.convertToXML(helpers, iReqResp);
                if (request != null)
                {
                    iReqResp.setRequest(request);
                }
            }
            catch (Exception e)
            {
                StringWriter out = new StringWriter();
                e.printStackTrace(new PrintWriter(out));
                callbacks.printError(out.toString());
            }
        });

        JMenuItem sendJSONToRepeater = new JMenuItem("Convert to JSON");
        sendJSONToRepeater.addActionListener(l -> {
            IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];

            try
            {
                byte[] request = Utilities.convertToJSON(helpers, iReqResp);
                if (request != null)
                {

                    iReqResp.setRequest(request);
                }
            } catch (Exception e)
            {
                StringWriter out = new StringWriter();
                e.printStackTrace(new PrintWriter(out));
                callbacks.printError(out.toString());
            }
        });

        menus.add(sendXMLToRepeater);
        menus.add(sendJSONToRepeater);

        return menus;
    }
}