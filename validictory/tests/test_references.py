from unittest import TestCase

import validictory


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
    }

    dangling_schema = {
        "$ref" : "noschema",
    }


    def test_references1(self):
        valid = {
            "prop1" : "test"
        }

        try:
            validictory.validate(valid, self.schema1, schemas=self.schemas)
            validictory.validate(valid, self.schema3, schemas=self.schemas)
        except ValueError as e:
            self.fail("Unexpected failure: %s" % e)

        invalid = [ 1, 2, 3]
        self.assertRaises(ValueError, validictory.validate, invalid, self.schema3)

    def test_references2(self):
        valid = [ 0, 14, 332 ]

        try:
            validictory.validate(valid, self.schema2, schemas=self.schemas)
            validictory.validate(valid, self.schema4, schemas=self.schemas)
        except ValueError as e:
            self.fail("Unexpected failure: %s" % e)

        invalid = { "test" : 1 }
        self.assertRaises(ValueError, validictory.validate, invalid, self.schema4, schemas=self.schemas)

    def test_references3(self):
        valid = {
            "prop1" : "test"
        }

        try:
            validictory.validate(valid, self.schema5, schemas=self.schemas)
        except ValueError as e:
            self.fail("Unexpected failure: %s" % e)

        invalid = { "noprop" : "fail" }
        self.assertRaises(ValueError, validictory.validate, invalid, self.schema5, schemas=self.schemas)

    def test_references4(self):
        prop2 = {
            "prop2" : 4
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

        try:
            validictory.validate(prop2, self.schema6, schemas=self.schemas)
            validictory.validate(prop23, self.schema7, schemas=self.schemas)
            validictory.validate(prop123, self.schema8, schemas=self.schemas)
        except ValueError as e:
            self.fail("Unexpected failure: %s" % e)

        self.assertRaises(ValueError, validictory.validate, prop2, self.schema7, schemas=self.schemas)
        self.assertRaises(ValueError, validictory.validate, prop2, self.schema8, schemas=self.schemas)
        self.assertRaises(ValueError, validictory.validate, prop23, self.schema8, schemas=self.schemas)

        invalid = {
            "prop1" : "test1",
            "prop2" : 4,
            "prop3" : "invalid"
        }

        self.assertRaises(ValueError, validictory.validate, invalid, self.schema8, schemas=self.schemas)

    def test_references5(self):
        valid = {
            "prop4" : True,
            "prop5" : 42,
        }

        try:
            validictory.validate(valid, self.schema9)
        except ValueError as e:
            self.fail("Unexpected failure: %s" % e)

        invalid = {
            "prop4" : "fail",
            "prop5" : 42,
        }

        self.assertRaises(ValueError, validictory.validate, invalid, self.schema9, schemas=self.schemas)
        
    def test_references6(self):
        data = "test"

        try:
            validictory.validate(data, self.dangling_schema)
        except ValueError as e:
            self.fail("Unexpected failure: %s" % e)

        self.assertRaises(ValueError, validictory.validate, data, self.dangling_schema, disallow_unknown_schemas=True)

