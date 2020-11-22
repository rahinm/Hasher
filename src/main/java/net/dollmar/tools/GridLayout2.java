package net.dollmar.tools;

import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.Insets;

public class GridLayout2 extends GridLayout
{
	private static final long serialVersionUID = -2125290047967095413L;

	public GridLayout2()
	{
		this(1, 0, 0, 0);
	}

	public GridLayout2(int rows, int cols)
	{
		this(rows, cols, 0, 0);
	}

	public GridLayout2(int rows, int cols, int hgap, int vgap)
	{
		super(rows, cols, hgap, vgap);
	}

	public Dimension preferredLayoutSize(Container parent)
	{
		synchronized (parent.getTreeLock())
		{
			Insets insets = parent.getInsets();
			int ncomponents = parent.getComponentCount();
			int nrows = getRows();
			int ncols = getColumns();
			if (nrows > 0) {
				ncols = (ncomponents + nrows - 1) / nrows;
			} else {
				nrows = (ncomponents + ncols - 1) / ncols;
			}
			int[] w = new int[ncols];
			int[] h = new int[nrows];
			for (int i = 0; i < ncomponents; i++)
			{
				int r = i / ncols;
				int c = i % ncols;
				Component comp = parent.getComponent(i);
				Dimension d = comp.getPreferredSize();
				if (w[c] < d.width) {
					w[c] = d.width;
				}
				if (h[r] < d.height) {
					h[r] = d.height;
				}
			}
			int nw = 0;
			for (int j = 0; j < ncols; j++) {
				nw += w[j];
			}
			int nh = 0;
			for (int i = 0; i < nrows; i++) {
				nh += h[i];
			}
			return new Dimension(insets.left + insets.right + nw + (ncols - 1) * getHgap(), 
					insets.top + insets.bottom + nh + (nrows - 1) * getVgap());
		}
	}

	public Dimension minimumLayoutSize(Container parent)
	{
		System.err.println("minimumLayoutSize");
		synchronized (parent.getTreeLock())
		{
			Insets insets = parent.getInsets();
			int ncomponents = parent.getComponentCount();
			int nrows = getRows();
			int ncols = getColumns();
			if (nrows > 0) {
				ncols = (ncomponents + nrows - 1) / nrows;
			} else {
				nrows = (ncomponents + ncols - 1) / ncols;
			}
			int[] w = new int[ncols];
			int[] h = new int[nrows];
			for (int i = 0; i < ncomponents; i++)
			{
				int r = i / ncols;
				int c = i % ncols;
				Component comp = parent.getComponent(i);
				Dimension d = comp.getMinimumSize();
				if (w[c] < d.width) {
					w[c] = d.width;
				}
				if (h[r] < d.height) {
					h[r] = d.height;
				}
			}
			int nw = 0;
			for (int j = 0; j < ncols; j++) {
				nw += w[j];
			}
			int nh = 0;
			for (int i = 0; i < nrows; i++) {
				nh += h[i];
			}
			return new Dimension(insets.left + insets.right + nw + (ncols - 1) * getHgap(), 
					insets.top + insets.bottom + nh + (nrows - 1) * getVgap());
		}
	}

	public void layoutContainer(Container parent)
	{
		synchronized (parent.getTreeLock())
		{
			Insets insets = parent.getInsets();
			int ncomponents = parent.getComponentCount();
			int nrows = getRows();
			int ncols = getColumns();
			if (ncomponents == 0) {
				return;
			}
			if (nrows > 0) {
				ncols = (ncomponents + nrows - 1) / nrows;
			} else {
				nrows = (ncomponents + ncols - 1) / ncols;
			}
			int hgap = getHgap();
			int vgap = getVgap();

			Dimension pd = preferredLayoutSize(parent);
			double sw = 1.0D * parent.getWidth() / pd.width;
			double sh = 1.0D * parent.getHeight() / pd.height;

			int[] w = new int[ncols];
			int[] h = new int[nrows];
			for (int i = 0; i < ncomponents; i++)
			{
				int r = i / ncols;
				int c = i % ncols;
				Component comp = parent.getComponent(i);
				Dimension d = comp.getPreferredSize();
				d.width = ((int)(sw * d.width));
				d.height = ((int)(sh * d.height));
				if (w[c] < d.width) {
					w[c] = d.width;
				}
				if (h[r] < d.height) {
					h[r] = d.height;
				}
			}
			int c = 0;
			for (int x = insets.left; c < ncols; c++)
			{
				int r = 0;
				for (int y = insets.top; r < nrows; r++)
				{
					int i = r * ncols + c;
					if (i < ncomponents) {
						parent.getComponent(i).setBounds(x, y, w[c], h[r]);
					}
					y += h[r] + vgap;
				}
				x += w[c] + hgap;
			}
		}
	}
}
