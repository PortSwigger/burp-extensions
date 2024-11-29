package burp;

import burp.BodyProcessor.JsonBodyProcessor;
import burp.BodyProcessor.XmlBodyProcessor;

import javax.swing.*;
import java.util.Collections;
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
        if (invocation.getToolFlag() != TOOL_INTRUDER && invocation.getInvocationContext() != CONTEXT_MESSAGE_EDITOR_REQUEST)
        {
            return Collections.emptyList();
        }

        JMenuItem sendXMLToRepeater = new JMenuItem("Convert to XML");
        sendXMLToRepeater.addActionListener(
                new ErrorHandlingActionListener(
                        callbacks,
                        new RequestUpdatingActionListener(
                                invocation,
                                new RequestProcessor(
                                        helpers,
                                        new XmlBodyProcessor(),
                                        "application/xml;charset=UTF-8"
                                )
                        )
                )
        );

        JMenuItem sendJSONToRepeater = new JMenuItem("Convert to JSON");
        sendJSONToRepeater.addActionListener(
                new ErrorHandlingActionListener(
                        callbacks,
                        new RequestUpdatingActionListener(
                                invocation,
                                new RequestProcessor(
                                        helpers,
                                        new JsonBodyProcessor(),
                                        "application/json;charset=UTF-8"
                                )
                        )
                )
        );

        return List.of(sendXMLToRepeater, sendJSONToRepeater);
    }
}