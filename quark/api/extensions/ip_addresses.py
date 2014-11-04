# Copyright (c) 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron.api import extensions
from neutron.common import exceptions
from neutron import manager
from neutron.openstack.common import log as logging
from neutron import wsgi
import webob

RESOURCE_NAME = 'ip_address'
RESOURCE_COLLECTION = RESOURCE_NAME + "es"
EXTENDED_ATTRIBUTES_2_0 = {
    RESOURCE_COLLECTION: {}
}

attr_dict = EXTENDED_ATTRIBUTES_2_0[RESOURCE_COLLECTION]
attr_dict[RESOURCE_NAME] = {'allow_post': True,
                            'allow_put': True,
                            'is_visible': True}

LOG = logging.getLogger(__name__)


class IpAddressesController(wsgi.Controller):

    def __init__(self, plugin):
        self._resource_name = RESOURCE_NAME
        self._plugin = plugin

    def index(self, request):
        context = request.context
        return {"ip_addresses":
                self._plugin.get_ip_addresses(context, **request.GET)}

    def show(self, request, id):
        context = request.context
        try:
            return {"ip_address":
                    self._plugin.get_ip_address(context, id)}
        except exceptions.NotFound:
            raise webob.exc.HTTPNotFound()

    def create(self, request, body=None):
        body = self._deserialize(request.body, request.get_content_type())
        try:
            return {"ip_address": self._plugin.create_ip_address(
                    request.context, body)}
        except exceptions.NotFound:
            raise webob.exc.HTTPNotFound()
        except exceptions.Conflict:
            raise webob.exc.HTTPConflict()

    def update(self, request, id, body=None):
        body = self._deserialize(request.body, request.get_content_type())
        try:
            return {"ip_address": self._plugin.update_ip_address(
                    request.context, id, body)}
        except exceptions.NotFound:
            raise webob.exc.HTTPNotFound()

    def delete(self, request, id):
        try:
            self._plugin.deallocate_ip_address(request.context, id)
        except exceptions.NotFound:
            raise webob.exc.HTTPNotFound()


class Ip_addresses(object):
    """IP Addresses support."""
    @classmethod
    def get_name(cls):
        return "IP Addresses for a tenant"

    @classmethod
    def get_alias(cls):
        return RESOURCE_COLLECTION

    @classmethod
    def get_description(cls):
        return "Expose functions for tenant IP Address management"

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/network/ext/"
                "ip_addresses/api/v2.0")

    @classmethod
    def get_updated(cls):
        return "2013-02-19T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        controller = IpAddressesController(manager.NeutronManager.get_plugin())
        return [extensions.ResourceExtension(
            Ip_addresses.get_alias(),
            controller)]
