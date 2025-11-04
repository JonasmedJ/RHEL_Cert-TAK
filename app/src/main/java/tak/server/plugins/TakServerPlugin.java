package tak.server.plugins;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation for TAK Server plugins.
 *
 * This annotation should be applied to plugin classes to provide
 * metadata about the plugin to the TAK Server plugin manager.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface TakServerPlugin {

    /**
     * The name of the plugin
     */
    String name();

    /**
     * A description of what the plugin does
     */
    String description() default "";

    /**
     * The version of the plugin
     */
    String version() default "1.0.0";
}
