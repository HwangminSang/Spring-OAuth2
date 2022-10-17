package io.security.oauth.resourceserver2;

import lombok.Data;

@Data
public class Photo {
    private String userId;
    private String photoId;
    private String photoTitle;
    private String photoDescription;
}