package net.dollmar.tools;

import java.io.IOException;
import java.io.InputStream;

import javax.crypto.Mac;

public class HmacInputStream extends InputStream {

	private final InputStream _inputStream;
	private final Mac _mac;
	
	
	public HmacInputStream(InputStream is, Mac mac) {
		this._inputStream = is;
		this._mac = mac;
	}
	
	

    @Override
    public int read() throws IOException
    {
        int i = _inputStream.read();
        if (i != -1)
            _mac.update((byte)i);
        return i;
    }

    @Override
    public int read(byte[] b) throws IOException
    {
        int i = _inputStream.read(b);
        if (i != -1)
            _mac.update(b, 0, i);
        return i;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException
    {
        int i = _inputStream.read(b, off, len);
        if (i != -1)
            _mac.update(b, off, i);
        return i;
    }

    @Override
    public long skip(long n) throws IOException
    {
        throw new IOException("Not supported");
    }

    @Override
    public int available() throws IOException
    {
        return _inputStream.available();
    }

    @Override
    public void close() throws IOException
    {
        _inputStream.close();
    }

    @Override
    public void mark(int readlimit)
    {}

    @Override
    public void reset() throws IOException
    {
        throw new IOException("Not supported");
    }

    @Override
    public boolean markSupported()
    {
        return false;
    }

}
