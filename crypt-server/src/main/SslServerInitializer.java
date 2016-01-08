package main;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import io.netty.handler.codec.Delimiters;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.SslHandler;

public class SslServerInitializer extends ChannelInitializer<SocketChannel> {

	private SSLContext sslCtx;

	public SslServerInitializer(SSLContext sslCtx) {
	        this.sslCtx = sslCtx;
	    }
	 
	
	private SslHandler newEngine(){
		
		SSLEngine engine = sslCtx.createSSLEngine() ; 	
		engine.setUseClientMode(false);
		engine.setNeedClientAuth(true);
		engine.setEnabledCipherSuites(new String[] {
                "TLS_RSA_WITH_AES_128_CBC_SHA"
            });
		//engine.setNeedClientAuth(false);
		
		return new SslHandler(engine);
	}
	
	@Override
	protected void initChannel(SocketChannel ch) throws Exception {
		ChannelPipeline pipeline = ch.pipeline();
		
		
		//
		pipeline.addLast(new LoggingHandler(LogLevel.INFO));
		  // Add SSL handler first to encrypt and decrypt everything.
        // In this example, we use a bogus certificate in the server sid	e
        // and accept any invalid certificates in the client side.
        // You will need something more complicated to identify both
        // and server in the real world.
        pipeline.addLast(newEngine());

        // On top of the SSL handler, add the text line codec.
        pipeline.addLast(new DelimiterBasedFrameDecoder(8192, Delimiters.lineDelimiter()));
        pipeline.addLast(new StringDecoder());
        pipeline.addLast(new StringEncoder());

        // and then business logic.
        pipeline.addLast(new EchoServerHandler());
		
	}

}
