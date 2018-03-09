package io.metropolislab.auth.model

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken

data class FirebaseAuthenticationToken(val token: String) : UsernamePasswordAuthenticationToken(null, null) {
    companion object {
        private val serialVersionUID = 1L
    }

}