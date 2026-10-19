"""FireMon policy drift report.

Compares the security rules of two firewalls (or two policies on them) held in
FireMon Security Manager and reports the drift: rules present on one side
only, and rules present on both whose source, destination, service,
application, action or other criteria differ. Optionally restricted to a
subset of rules -- a change request, an application, a category -- and
delivered by email.

Standard library only. See README.md for usage and DEPLOYMENT.md for install.
"""

__version__ = "1.2.0"
