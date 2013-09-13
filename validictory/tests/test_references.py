from unittest import TestCase

from validictory import validate, ValidationError


class TestReferences(TestCase):
    schema1 = {
        "type" : "object",
        "properties" : {
            "prop1" : {"type": "string"},
        },
    }
    schema2 = {
        "type" : "array",
        "items" : { "type" : "integer" },
    }
    schema3 = {
        "type" : "object",
        "$ref" : "schema1",
    }
    schema4 = {
        "$ref" : "schema2",
    }
    schema5 = {
        "allOf" : [
            {"$ref":"schema1"},
        ]
    }
    schema6 = {
        "type" : "object",
        "properties" : {
            "prop2" : {"type": "integer"},
        },
    }
    schema7 = {
        "type" : "object",
        "allOf" : [
            {"$ref" : "schema6"},
            { "type" : "object", "properties" : { "prop3" : { "type" : "boolean" } } },
        ]
    }

    schema8 = {
        "allOf" : [
            {"$ref":"schema1"},
            {"$ref":"schema7"},
        ]
    }

    schema9 = {
        "allOf" : [
            { "type" : "object", "properties" : { "prop4" : { "type" : "boolean" } } },
            { "type" : "object", "properties" : { "prop5" : { "type" : "integer" } } },
        ]
    }

    schema_allOf = {
        "type" : "object",
        "allOf" : [
            {"$ref" : "schema7"},
            { "type" : "object", "properties" : { "prop6" : { "type" : "boolean" } } },
        ]
    }

    schema_oneOf = {
        "type" : "object",
        "oneOf" : [
            {"$ref" : "schema7"},
            { "type" : "object", "properties" : { "prop6" : { "type" : "boolean" } } },
        ]
    }

    schema_allOfoneOf = {
        "type" : "object",
        "required" : [ "prop10" ],
        "properties" : {
            "prop10" : {
                "type" : "object",
                "allOf" : [ {
                    "type" : "object",
                    "oneOf" : [ {
                        "type" : "object",
                        "properties" : {
                            "prop7" : { "type" : "boolean" }
                        }
                    }, {
                        "type" : "object",
                        "properties" : {
                            "prop8" : { "type" : "integer" }
                        }
                    },
                    ]
                }, { "type" : "object", "properties" : { "prop9" : { "type" : "string" } } }
                ]
            }
        }
    }

    schema_refAllOfoneOf = {
        "type" : "object",
        "$ref" : "schema_allOfoneOf",
    }

    schema_anyOf = {
        "type" : "object",
        "anyOf" : [
            {"$ref" : "schema7"},
            { "type" : "object", "properties" : { "prop6" : { "type" : "boolean" } } },
        ]
    }

    schema_not = {
        "type" : "object",
        "not" : {"$ref" : "schema7"},
    }

    schemas = {
        'schema1' : schema1,
        'schema2' : schema2,
        'schema3' : schema3,
        'schema4' : schema4,
        'schema5' : schema5,
        'schema6' : schema6,
        'schema7' : schema7,
        'schema8' : schema8,
        'schema9' : schema9,
        'schema_allOf' : schema_allOf,
        'schema_oneOf' : schema_oneOf,
        'schema_anyOf' : schema_anyOf,
        'schema_allOfoneOf' : schema_allOfoneOf,
        'schema_not' : schema_not,
    }

    dangling_schema = {
        "$ref" : "noschema",
    }

    def _validate(self, *args, **kwargs):
        kwargs['schemas'] = kwargs.get('schemas', self.schemas)
        kwargs['disallow_unknown_schemas'] = kwargs.get('disallow_unknown_schemas', True)
        kwargs['disallow_unknown_properties'] = kwargs.get('disallow_unknown_properties', True)
        return validate(*args, **kwargs)

    def test_references1(self):
        valid = {
            "prop1" : "test"
        }

        try:
            self._validate(valid, self.schema1)
            self._validate(valid, self.schema3)
        except ValidationError as e:
            self.fail("Unexpected failure: %s" % e)

        invalid = [ 1, 2, 3]
        self.assertRaises(ValidationError, self._validate, invalid, self.schema3)

    def test_references2(self):
        valid = [ 0, 14, 332 ]

        try:
            self._validate(valid, self.schema2)
            self._validate(valid, self.schema4)
        except ValidationError as e:
            self.fail("Unexpected failure: %s" % e)

        invalid = { "test" : 1 }
        self.assertRaises(ValidationError, self._validate, invalid, self.schema4)

    def test_references3(self):
        valid = {
            "prop1" : "test"
        }

        try:
            self._validate(valid, self.schema5)
        except ValidationError as e:
            self.fail("Unexpected failure: %s" % e)

        invalid = { "noprop" : "fail" }
        self.assertRaises(ValidationError, self._validate, invalid, self.schema5)

    def test_references4(self):
        prop2 = {
            "prop2" : 4
        }

        prop3 = {
            "prop3" : True
        }

        prop23 = {
            "prop2" : 4,
            "prop3" : True
        }

        prop123 = {
            "prop1" : "test1",
            "prop2" : 4,
            "prop3" : True
        }

        self._validate(prop2, self.schema6)
        self._validate(prop23, self.schema7)
        self._validate(prop123, self.schema8)

        self.assertRaises(ValidationError, self._validate, prop2, self.schema7)
        self.assertRaises(ValidationError, self._validate, prop3, self.schema7)
        self.assertRaises(ValidationError, self._validate, prop2, self.schema8)
        self.assertRaises(ValidationError, self._validate, prop23, self.schema8)

        invalid = {
            "prop1" : "test1",
            "prop2" : 4,
            "prop3" : "invalid"
        }

        self.assertRaises(ValidationError, self._validate, invalid, self.schema8)

    def test_references5(self):
        valid = {
            "prop4" : True,
            "prop5" : 42,
        }

        try:
            self._validate(valid, self.schema9)
        except ValidationError as e:
            self.fail("Unexpected failure: %s" % e)

        invalid1 = {
            "prop4" : "fail",
            "prop5" : 42,
        }

        invalid2 = {
            "prop5" : 42,
        }

        invalid3 = {
            "prop4" : True,
        }

        self.assertRaises(ValidationError, self._validate, invalid1, self.schema9)
        self.assertRaises(ValidationError, self._validate, invalid2, self.schema9)
        self.assertRaises(ValidationError, self._validate, invalid3, self.schema9)

    def test_allOf(self):
        valid = {
            "prop3" : True,
            "prop6" : True,
            "prop2" : 42,
        }

        try:
            self._validate(valid, self.schema_allOf)
        except ValidationError as e:
            self.fail("Unexpected failure: %s" % e)

        invalid1 = {
            "prop4" : "fail",
            "prop5" : 42,
        }

        invalid2 = {
            "prop5" : 42,
        }

        invalid3 = {
            "prop4" : True,
        }

        invalid4 = {
            "prop3" : True,
            "prop5" : 42,
        }

        invalid5 = {
            "prop2" : 42,
        }

        invalid6 = {
            "prop3" : True,
        }

        invalid7 = {
            "prop6" : True,
        }

        self.assertRaises(ValidationError, self._validate, invalid1, self.schema_allOf)
        self.assertRaises(ValidationError, self._validate, invalid2, self.schema_allOf)
        self.assertRaises(ValidationError, self._validate, invalid3, self.schema_allOf)
        self.assertRaises(ValidationError, self._validate, invalid4, self.schema_allOf)
        self.assertRaises(ValidationError, self._validate, invalid5, self.schema_allOf)
        self.assertRaises(ValidationError, self._validate, invalid6, self.schema_allOf)
        self.assertRaises(ValidationError, self._validate, invalid7, self.schema_allOf)

    def test_oneOf(self):
        valid1 = {
            "prop3" : True,
            "prop2" : 42,
        }

        valid2 = {
            "prop6" : True,
        }


        try:
            self._validate(valid1, self.schema_oneOf)
            self._validate(valid2, self.schema_oneOf)
        except ValidationError as e:
            self.fail("Unexpected failure: %s" % e)

        invalid1 = {
            "prop3" : True,
        }

        invalid2 = {
            "prop2" : 42,
        }

        invalid3 = {
            "prop3" : True,
            "prop2" : 42,
            "prop6" : True,
        }

        invalid4 = {
            "test" : "fail",
        }

        invalid5 = {
            "prop3" : True,
            "prop6" : True,
        }

        self.assertRaises(ValidationError, self._validate, invalid1, self.schema_oneOf)
        self.assertRaises(ValidationError, self._validate, invalid2, self.schema_oneOf)
        self.assertRaises(ValidationError, self._validate, invalid3, self.schema_oneOf)
        self.assertRaises(ValidationError, self._validate, invalid4, self.schema_oneOf)
        self.assertRaises(ValidationError, self._validate, invalid5, self.schema_oneOf)

    def test_allOfoneOf(self):
        valid1 = {
            "prop10" : {
                "prop9" : "test",
                "prop7" : True,
            }
        }

        valid2 = {
            "prop10" : {
                "prop9" : "test",
                "prop8" : 42,
            }
        }

        try:
            self._validate(valid1, self.schema_allOfoneOf)
            self._validate(valid2, self.schema_allOfoneOf)
            self._validate(valid1, self.schema_refAllOfoneOf)
            self._validate(valid2, self.schema_refAllOfoneOf)
        except ValidationError as e:
            self.fail("Unexpected failure: %s" % e)

        invalid1 = {
            "prop10" : {
                "prop9" : "test",
                "prop7" : True,
                "prop8" : 42,
            }
        }

        invalid2 = {
            "prop10" : {
                "prop9" : "test",
            }
        }

        invalid3 = {
            "prop10" : {
                "prop7" : True,
            }
        }

        invalid4 = {
            "prop10" : {
                "prop8" : 42,
            }
        }

        invalid5 = {
            "prop10" : {
                "test" : "fail",
            }
        }

        invalid6 = {
            "test" : "fail",
        }

        invalid7 = {
            "prop10" : {
                "prop9" : "test",
                "prop7" : True,
                "unknown" : 1,
            }
        }

        self.assertRaises(ValidationError, self._validate, invalid1, self.schema_allOfoneOf)
        self.assertRaises(ValidationError, self._validate, invalid2, self.schema_allOfoneOf)
        self.assertRaises(ValidationError, self._validate, invalid3, self.schema_allOfoneOf)
        self.assertRaises(ValidationError, self._validate, invalid4, self.schema_allOfoneOf)
        self.assertRaises(ValidationError, self._validate, invalid5, self.schema_allOfoneOf)
        self.assertRaises(ValidationError, self._validate, invalid6, self.schema_allOfoneOf)
        self.assertRaises(ValidationError, self._validate, invalid7, self.schema_allOfoneOf)
        self.assertRaises(ValidationError, self._validate, invalid1, self.schema_refAllOfoneOf)
        self.assertRaises(ValidationError, self._validate, invalid2, self.schema_refAllOfoneOf)
        self.assertRaises(ValidationError, self._validate, invalid3, self.schema_refAllOfoneOf)
        self.assertRaises(ValidationError, self._validate, invalid4, self.schema_refAllOfoneOf)
        self.assertRaises(ValidationError, self._validate, invalid5, self.schema_refAllOfoneOf)
        self.assertRaises(ValidationError, self._validate, invalid6, self.schema_refAllOfoneOf)
        self.assertRaises(ValidationError, self._validate, invalid7, self.schema_refAllOfoneOf)

    def test_anyOf(self):
        valid1 = {
            "prop6" : True,
        }

        valid2 = {
            "prop2" : 42,
            "prop3" : True,
        }

        try:
            self._validate(valid1, self.schema_anyOf)
            self._validate(valid2, self.schema_anyOf)
        except ValidationError as e:
            self.fail("Unexpected failure: %s" % e)

        invalid1 = {
            "test" : "fail",
        }

        invalid2 = {
            "prop2" : 42,
        }

        invalid3 = {
            "prop3" : True,
        }


        self.assertRaises(ValidationError, self._validate, invalid1, self.schema_anyOf)
        self.assertRaises(ValidationError, self._validate, invalid2, self.schema_anyOf)
        self.assertRaises(ValidationError, self._validate, invalid3, self.schema_anyOf)

    def test_not(self):
        valid1 = {
            "test" : 1,
        }

        valid2 = {
            "prop2" : 42,
        }

        valid3 = {
            "prop3" : True,
        }

        valid4 = {
            "prop2" : "42",
            "prop3" : True,
        }

        try:
            self._validate(valid1, self.schema_not)
            self._validate(valid2, self.schema_not)
            self._validate(valid3, self.schema_not)
            self._validate(valid4, self.schema_not)
        except ValidationError as e:
            self.fail("Unexpected failure: %s" % e)

        invalid = {
            "prop2" : 42,
            "prop3" : True,
        }

        self.assertRaises(ValidationError, self._validate, invalid, self.schema_not)
        
    def test_references10(self):
        data = "test"

        try:
            self._validate(data, self.dangling_schema, disallow_unknown_schemas=False)
        except ValidationError as e:
            self.fail("Unexpected failure: %s" % e)

        self.assertRaises(ValidationError, self._validate, data, self.dangling_schema, disallow_unknown_schemas=True)

