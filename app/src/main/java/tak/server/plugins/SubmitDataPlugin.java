package tak.server.plugins;

import java.util.Map;

public interface SubmitDataPlugin {
    Object onSubmitData(String pathVariable, Map<String, String[]> allRequestParams);
}