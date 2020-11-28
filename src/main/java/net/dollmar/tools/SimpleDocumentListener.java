package net.dollmar.tools;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * 	 Ref: https://stackoverflow.com/questions/3953208/value-change-listener-to-jtextfield
 *
 */
@FunctionalInterface
public interface SimpleDocumentListener extends DocumentListener {
    void update(DocumentEvent e);

    @Override
    default void insertUpdate(DocumentEvent e) {
        update(e);
    }
    @Override
    default void removeUpdate(DocumentEvent e) {
        update(e);
    }
    @Override
    default void changedUpdate(DocumentEvent e) {
        update(e);
    }
}
