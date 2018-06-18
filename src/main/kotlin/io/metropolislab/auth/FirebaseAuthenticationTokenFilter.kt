package io.metropolislab.auth

import io.metropolislab.auth.model.FirebaseAuthenticationToken
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import java.io.IOException
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Filter that catches Firebase token, authenticate it and include it security context
 */
class FirebaseAuthenticationTokenFilter
        : AbstractAuthenticationProcessingFilter("/**") {

    override fun attemptAuthentication(request: HttpServletRequest,
                                       response: HttpServletResponse)
            : Authentication {
        val authToken = request.getHeader(TOKEN_HEADER)
        if (authToken.isNullOrEmpty() || !authToken.startsWith(TOKEN_PREFIX)) {
            throw AuthenticationCredentialsNotFoundException("Invalid auth token")
        }

        return authenticationManager.authenticate(FirebaseAuthenticationToken(authToken.split(TOKEN_PREFIX)[1]))
    }

    /**
     * Make sure the rest of the filterchain is satisfied

     * @param request
     * *
     * @param response
     * *
     * @param chain
     * *
     * @param authResult
     * *
     * @throws IOException
     * *
     * @throws ServletException
     */
    @Throws(IOException::class, ServletException::class)
    override fun successfulAuthentication(request: HttpServletRequest,
                                          response: HttpServletResponse,
                                          chain: FilterChain,
                                          authResult: Authentication) {
        super.successfulAuthentication(request, response, chain, authResult)

        // As this authentication is in HTTP header, after success we need to continue the request normally
        // and return the response as if the resource was not secured at all
        chain.doFilter(request, response)
    }

    companion object {
        private val TOKEN_HEADER = "Authorization"
        private val TOKEN_PREFIX = "Bearer "
    }
}