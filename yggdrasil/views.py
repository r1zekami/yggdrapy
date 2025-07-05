"""
It is a temporary thing while there is no frontend, placeholder for now
"""
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods


@csrf_exempt
@require_http_methods(["GET"])
def main_page(request):
    """Main page for Yggdrasil protocol placeholder"""
    
    html_content = """
        <h1>Yggdrasil Auth Section</h1>
        <p>This is the main authentication server for Yggdrasil protocol.</p>
        <p>Available endpoints:</p>
        <ul>
            <li><a href="/yggdrasil/auth/">Authentication</a></li>
            <li><a href="/yggdrasil/account/">Account Management</a></li>
            <li><a href="/yggdrasil/session/">Session Management</a></li>
            <li><a href="/yggdrasil/services/">Services</a></li>
        </ul>
        
        <h2>Configuration</h2>
        <p>Or, if your launcher supports custom API servers but not via authlib-injector, use the following URLs:</p>
        <ul>
            <li><strong>Authentication Server:</strong> https://{your.server.address}/yggdrasil/auth</li>
            <li><strong>Account Server:</strong> https://{your.server.address}/yggdrasil/account</li>
            <li><strong>Session Server:</strong> https://{your.server.address}/yggdrasil/session</li>
            <li><strong>Services Server:</strong> https://{your.server.address}/yggdrasil/services</li>
        </ul>
        
        <h3>Configuring your server</h3>
        <h4>Minecraft 1.16 and later</h4>
        <p>On recent versions of Minecraft, you can use Yggdrasil on an unmodified Vanilla server. To do so, add the following arguments before you specify the jar file when you start the server:</p>
        <pre><code>-Dminecraft.api.env=custom
-Dminecraft.api.auth.host=https://{your.server.address}/yggdrasil/auth
-Dminecraft.api.account.host=https://{your.server.address}/yggdrasil/account
-Dminecraft.api.session.host=https://{your.server.address}/yggdrasil/session
-Dminecraft.api.services.host=https://{your.server.address}/yggdrasil/services</code></pre>
        """
    return HttpResponse(html_content.encode('utf-8'), content_type='text/html; charset=utf-8')

