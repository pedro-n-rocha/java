package main;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Logger;


import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class Main {
	
	private final static Logger log = Logger.getLogger(Main.class.getName());
	
	static final String HOST = "127.0.0.1";
    static final int PORT = 1234;
    
    String ksfile = "keystore";
	String kspwd = "123qwe";
	
	String tsfile = "truststore";
	String tspwd = "123qwe";

	
	public static void main(String[] args) 
	{
		
		log.info("|_starting_|\n\n");
		try 
		{
			new Main().init();
		} catch (Exception ex) 
		{
			log.warning(ex.getMessage());
		}
		log.info("\n\n|_stoped_|");
	}
	
	private KeyStore initStore(String file, String pwd) throws KeyStoreException,
	NoSuchAlgorithmException, CertificateException, IOException 
	{
		KeyStore s = KeyStore.getInstance("JKS");
		InputStream is = new FileInputStream(file);
		s.load(is, pwd.toCharArray());
		is.close();
		return s;
	}
	
	public void init() throws InterruptedException, IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException
	{
		KeyStore ks = initStore(ksfile, kspwd);
		KeyStore ts = initStore(tsfile, tspwd);
		

		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
				.getDefaultAlgorithm());
		kmf.init(ks, kspwd.toCharArray());
		
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory
				.getDefaultAlgorithm());
		tmf.init(ts);
		
		SSLContext sslctx = SSLContext.getInstance("TLS");
		
		//sslctx.init( kmf.getKeyManagers() , InsecureTrustManagerFactory.INSTANCE.getTrustManagers(), null);
		sslctx.init( kmf.getKeyManagers() , tmf.getTrustManagers(), null);
		
        EventLoopGroup group = new NioEventLoopGroup();
        try {
            Bootstrap b = new Bootstrap();
            b.group(group)
             .channel(NioSocketChannel.class)
             .handler(new SecureChatClientInitializer(sslctx));

            // Start the connection attempt.
            Channel ch = b.connect(HOST, PORT).sync().channel();

            // Read commands from the stdin.
            ChannelFuture lastWriteFuture = null;
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            for (;;) {
                String line = in.readLine();
                if (line == null) {
                    break;
                }

                // Sends the received line to the server.
                lastWriteFuture = ch.writeAndFlush(line + "\r\n");

                // If user typed the 'bye' command, wait until the server closes
                // the connection.
                if ("bye".equals(line.toLowerCase())) {
                    ch.closeFuture().sync();
                    break;
                }
            }

            // Wait until all messages are flushed before closing the channel.
            if (lastWriteFuture != null) {
                lastWriteFuture.sync();
            }
        } finally {
            // The connection is closed automatically on shutdown.
            group.shutdownGracefully();
        }
    }
}
