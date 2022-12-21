import 'package:collection/collection.dart';

enum ResType {
  resNullType(0x0000),
  resStringPoolType(0x0001),
  resTableType(0x0002),
  xmlType(0x0003),
  // Chunk types in [xmlType]
  xmlFirstChunkType(0x0100),
  xmlStartNamespaceType(0x0100),
  xmlEndNamespaceType(0x0101),
  xmlStartElementType(0x0102),
  xmlEndElementType(0x0103),
  xmlCdataType(0x0104),
  xmlLastChunkType(0x017f),
  // This contains a uint32_t array mapping strings in the string
  // pool back to resource identifiers.  It is optional.
  xmlResourceMapType(0x0180),
  // Chunk types in [tableType]
  tablePackageType(0x0200),
  tableTypeType(0x0201),
  tableTypeSpecType(0x0202),
  ;

  const ResType(this.value);

  final int value;

  static ResType? forInt(int value) {
    return values.firstWhereOrNull((el) => el.value == value);
  }
}

enum ResDataType {
  // Contains no data.
  typeNull(0x00),
  // The 'data' holds the another resource identifier.
  typeReference(0x01),
  // The 'data' holds an attribute resource identifier.
  typeAttribute(0x02),
  // The 'data' holds an index into the string pool.
  typeString(0x03),
  // The 'data' holds a single-precision floating point number.
  typeFloat(0x04),
  // The 'data' holds a complex number encoding a dimension value,
  // such as "100in".
  typeDimension(0x05),
  // The 'data' holds a complex number encoding a fraction of a
  // container.
  typeFraction(0x06),
  // The 'data' is a raw integer value of the form n..n.
  typeIntDec(0x10),
  // The 'data' is a raw integer value of the form 0xn..n.
  typeIntHex(0x11),
  // The 'data' is either 0 or 1, for input "false" or "true" respectively.
  typeIntBool(0x12),
  // The 'data' is a raw integer value of the form #aarrggbb.
  typeIntColorARGB8(0x1c),
  // The 'data' is a raw integer value of the form #rrggbb.
  typeIntColorRGB8(0x1d),
  // The 'data' is a raw integer value of the form #argb.
  typeIntColorARGB4(0x1e),
  // The 'data' is a raw integer value of the form #rgb.
  typeIntColorRGB4(0x1f),
  ;

  const ResDataType(this.value);

  final int value;

  static ResDataType? forInt(int value) {
    return values.firstWhereOrNull((el) => el.value == value);
  }
}

// Where the unit type information is.  This gives us 16 possible
// types, as defined below.
const complexUnitShift = 0;
const complexUnitMask = 0xf;

enum ResComplexUnitType {
  // TYPE_DIMENSION: Value is raw pixels.
  complexUnitPx(0, 'px'),
  // TYPE_DIMENSION: Value is Device Independent Pixels.
  complexUnitDip(1, 'dp'),
  // TYPE_DIMENSION: Value is a Scaled device independent Pixels.
  complexUnitSp(2, 'sp'),
  // TYPE_DIMENSION: Value is in points.
  complexUnitPt(3, 'pt'),
  // TYPE_DIMENSION: Value is in inches.
  complexUnitIn(4, 'in'),
  // TYPE_DIMENSION: Value is in millimeters.
  complexUnitMm(5, 'mm'),
  ;

  const ResComplexUnitType(this.value, this.suffix);

  final int value;

  final String suffix;

  static ResComplexUnitType? forInt(int value) {
    return values.firstWhereOrNull((el) => el.value == value);
  }
}

// Where the radix information is, telling where the decimal place
// appears in the mantissa.  This give us 4 possible fixed point
// representations as defined below.
const complexRadixShift = 4;
const complexRadixMask = 0x3;

enum ResComplexRadixType {
  // The mantissa is an integral number -- i.e., 0xnnnnnn.0
  complexRadix23p0(0),
  // The mantissa magnitude is 16 bits -- i.e, 0xnnnn.nn
  complexRadix16p7(1),
  // The mantissa magnitude is 8 bits -- i.e, 0xnn.nnnn
  complexRadix8p15(2),
  // The mantissa magnitude is 0 bits -- i.e, 0x0.nnnnnn
  complexRadix0p23(3),
  ;

  const ResComplexRadixType(this.value);

  final int value;

  static ResComplexRadixType? forInt(int value) {
    return values.firstWhereOrNull((el) => el.value == value);
  }
}

// Where the actual value is.  This gives us 23 bits of
// precision.  The top bit is the sign.
const complexFractionShift = 8;
const complexFractionMask = 0xffffff;

enum ResComplexFractionType {
  // TYPE_FRACTION: A basic fraction of the overall size.
  complexUnitFraction(0),
  // TYPE_FRACTION: A fraction of the parent size.
  complexUnitFractionParent(1),
  ;

  const ResComplexFractionType(this.value);

  final int value;

  static ResComplexFractionType? forInt(int value) {
    return values.firstWhereOrNull((el) => el.value == value);
  }
}
