package com.rdmishra.auth.Exception;

public class ResourcesNotFoundException extends RuntimeException {

    public ResourcesNotFoundException(String sms) {
        super(sms);
    }

    public ResourcesNotFoundException() {
        super("User not found at given id");
    }
}
