// Demo emails. All fictional: reserved documentation IPs (192.0.2.0/24) and
// reserved TLDs (.test) only, so nothing here can accidentally point at a
// real victim or a real person. Each carries a one-line teaching note shown
// under the result.

export interface Sample {
  id: string;
  title: string;
  band: string;
  note: string;
  raw: string;
}

const obviousPhishing = `From: Security Team <alerts@secure-account-verify.test>
To: victim@recipient.test
Subject: URGENT: YOUR ACCOUNT WILL BE SUSPENDED WITHIN 24 HOURS
Date: Mon, 3 Mar 2026 09:00:00 +0000

URGENT ACTION REQUIRED

Dear Customer,

We detected unusual sign-in activity on your account. Your account will be
blocked today unless you confirm your identity immediately.

Please reply with your password and the 6-digit verification code we just
sent to your phone. This is required to restore your account.

Also review your details here: http://192.0.2.45/login.php

See the attached invoice for full details: invoice.pdf.exe

Failure to comply within 24 hours will result in permanent closure.

Security Team`;

const sophisticatedPhishing = `From: "IT Service Desk" <itdesk@ms-support-portal.test>
Reply-To: helpdesk@ms-secure-login.test
To: finance@recipient.test
Return-Path: <bounce@ms-support-portal.test>
Subject: RE: Password expires today
Authentication-Results: mx.recipient.test; spf=pass smtp.mailfrom=ms-support-portal.test; dkim=fail; dmarc=fail header.from=recipient.test
Message-ID: <20260303@outbound-bulk-07.ms-support-portal.test>
Date: Tue, 3 Mar 2026 10:15:00 +0000
Received: from outbound-bulk-07.ms-support-portal.test (unknown [192.0.2.77])
	by mx.recipient.test with ESMTP; Tue, 3 Mar 2026 10:15:00 +0000

Hello,

Your password expires today. Please sign in to review your account and keep
access, otherwise the mailbox will be deactivated.

Review your invoice here:
https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fms-secure-login.test%2Finvoice

Regards,
IT Service Desk`;

const fakeMicrosoft = `From: "Microsoft 365" <no-reply@microsoftonline-password.test>
To: victim@recipient.test
Subject: Mailbox storage full - password expires today
Date: Tue, 3 Mar 2026 08:00:00 +0000

Dear User,

Your mailbox has exceeded its storage limit and your password expires today.

To avoid losing your emails, verify your identity now by confirming your
password and the one-time code we sent you.

Click here: https://microsoftonline.account-verify.test/login

Display text above points elsewhere than the link.

Regards,
Microsoft 365 Support`;

const parcelScam = `From: Delivery Notices <noreply@parcel-redelivery.test>
To: victim@recipient.test
Subject: Delivery attempt failed
Date: Tue, 3 Mar 2026 12:00:00 +0000

Dear Customer,

We could not deliver your parcel. A redelivery fee of INR 25 must be paid
today to avoid return to sender.

Scan or open the link to pay within 24 hours:
https://rb.gy/parcel25

Pay the customs duty immediately to release your parcel to avoid penalties.`;

const invoiceBec = `From: CEO <ceo@company-partners.test>
Reply-To: ceo.payments@gmail.com
To: accounts@recipient.test
Subject: Re: Invoice payment - urgent, confidential
Authentication-Results: mx.recipient.test; spf=pass smtp.mailfrom=company-partners.test; dkim=pass header.d=company-partners.test; dmarc=pass header.from=company-partners.test
Date: Tue, 3 Mar 2026 14:00:00 +0000
Received: from mail.company-partners.test (mail.company-partners.test [192.0.2.10])
	by mx.recipient.test with ESMTP; Tue, 3 Mar 2026 14:00:00 +0000

Hi,

Are you available? I need you to process an urgent wire transfer before I go
into a meeting - I cannot call right now, please keep this between us.

We have new bank details for the supplier, use the account in the attached
note. Kindly confirm once done.

Thanks,
CEO`;

const legitimate = `From: Notifications <notifications@github.com>
To: victim@recipient.test
Subject: [GitHub] A new device signed in to your account
Authentication-Results: mx.recipient.test; spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com header.s=fcap header.i=@github.com; dmarc=pass header.from=github.com
Date: Tue, 3 Mar 2026 16:00:00 +0000
Received: from github.com (github.com [192.0.2.33]) by mx.recipient.test; Tue, 3 Mar 2026 16:00:00 +0000

Hey there,

A new device signed in to your GitHub account.

If this was you, no action is needed. If you do not recognise this device,
you can review active sessions from your security settings page:

https://github.com/settings/security

Thanks,
The GitHub Team`;

export const SAMPLES: Sample[] = [
  {
    id: 'obvious',
    title: 'Obvious phishing (body only)',
    band: 'High Risk',
    note: 'What to notice: manufactured urgency, a generic greeting, a direct password + OTP request, a raw IP link, an .exe attachment and a threat of closure. Each is a classic tell; no header analysis was needed to reach the verdict.',
    raw: obviousPhishing
  },
  {
    id: 'sophisticated',
    title: 'Sophisticated phishing (full headers)',
    band: 'High Risk',
    note: 'What to notice: the tone is professional and there is nothing dramatic in the wording. The signals are structural: Reply-To on a different domain, dmarc=fail with spf=pass (so authentication passes but not for the From you see), and a redirect wrapper hiding a lookalike domain. Quiet signals, each small, adding up.',
    raw: sophisticatedPhishing
  },
  {
    id: 'microsoft',
    title: 'Fake Microsoft 365 warning (full headers)',
    band: 'High Risk',
    note: 'What to notice: mailbox-full + password-expiry is the classic IT-helpdesk pretext, the visible link text claims Microsoft while the href is an account-verify lookalike, and it asks for a one-time code. The brand is claimed but no genuine Microsoft domain appears anywhere.',
    raw: fakeMicrosoft
  },
  {
    id: 'parcel',
    title: 'Fake parcel delivery (body only)',
    band: 'Suspicious → High',
    note: 'What to notice: a small fee rather than a big ask, a shortened link you cannot see through, a generic greeting and deadline pressure. The Indian-context customs-duty + immediate-payment line is the same trick with a local costume.',
    raw: parcelScam
  },
  {
    id: 'bec',
    title: 'Invoice / BEC-style (full headers)',
    band: 'Suspicious → High',
    note: 'What to notice: there is no link and no attachment, so most URL and malware rules stay silent. The story is carried by content and headers: new bank details, secrecy, urgency, Reply-To on free webmail - while authentication actually passes. The small mitigation must not rescue it.',
    raw: invoiceBec
  },
  {
    id: 'legit',
    title: 'Legitimate email (full headers)',
    band: 'Low Risk',
    note: 'What to notice: authentication passes and aligns, the link points back at the sending domain, and there is no pressure or request for secrets. Note the coverage panel and the standing caveat - passing authentication does not prove an email is safe.',
    raw: legitimate
  }
];

