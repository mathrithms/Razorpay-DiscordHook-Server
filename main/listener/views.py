from django.http import HttpResponse, HttpResponseForbidden, HttpResponseServerError
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from django.utils.encoding import force_bytes
from hashlib import sha256
import hmac

import json
from discord_webhook import DiscordWebhook, DiscordEmbed

import os
from dotenv import load_dotenv

load_dotenv('../../.env')

@require_POST
@csrf_exempt
def webhook(request):
    raw_body = request.body
    webhook_secret = os.getenv('RAZORPAY_WEBHOOK_SECRET')
    webhook_signature = request.headers.get('X-Razorpay-Signature')

    if webhook_signature is None:
        return HttpResponseForbidden('Permission denied.')
    
    sha_name, signature = webhook_signature.split('=')
    if sha_name != 'sha256':
        return HttpResponseServerError('Operation not supported.', status=501)

    mac = hmac.new(force_bytes(webhook_secret), msg=force_bytes(raw_body), digestmod=sha256)
    if not hmac.compare_digest(force_bytes(mac.hexdigest()), force_bytes(signature)):
        return HttpResponseForbidden('Permission denied.')

    body = json.loads(str(request.body, encoding='utf-8'))
    event = body["event"]

    webhook_url = os.getenv('DISCORD_WEBHOOK_CHANNEL_URL')
    webhook = DiscordWebhook(url=webhook_url)

    if "payment" in body['contains']:
        color = "0000FF"
        if body['payload']['payment']['entity']['error_code'] is not None:
            color = "FF0000"

        embed = DiscordEmbed(title = f"{' '.join(event.split('.')).upper()}", description = f"This webhook is triggered by the {event} event", color = color)
        embed.set_author(
            name = "Razorpay"
        )   
        
        embed.add_embed_field(name = "Email", value=f"```{body['payload']['payment']['entity']['email']}```")
        embed.add_embed_field(name = "Contact", value=f"```{body['payload']['payment']['entity']['contact']}```")

        webhook.add_embed(embed=embed)
        webhook.execute()

    elif body['contains'][0] == "invoice":
        color = "0000FF"
        if body['payload']['invoice']['entity']['error_code'] is not None:
            color = "FF0000"

        embed = DiscordEmbed(title = f"{' '.join(event.split('.')).upper()}", description = f"This webhook is triggered by the {event} event", color = color)
        embed.set_author(
            name = "Razorpay"
        )   
        
        embed.add_embed_field(name = "Email", value=f"```{body['payload']['invoice']['entity']['email']}```")
        embed.add_embed_field(name = "Contact", value=f"```{body['payload']['invoice']['entity']['contact']}```")

        webhook.add_embed(embed=embed)
        webhook.execute()
    
    else:
        return HttpResponse(status=204)

    return HttpResponse(f"{' '.join(event.split('.')).upper()}")
